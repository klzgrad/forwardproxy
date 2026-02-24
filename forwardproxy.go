// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Caching is purposefully ignored.

package forwardproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/forwardproxy/httpclient"
	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements a forward proxy.
//
// EXPERIMENTAL: This handler is still experimental and subject to breaking changes.
type Handler struct {
	logger *zap.Logger

	// Filename of the PAC file to serve.
	PACPath string `json:"pac_path,omitempty"`

	// If true, the Forwarded header will not be augmented with your IP address.
	HideIP bool `json:"hide_ip,omitempty"`

	// If true, the Via header will not be added.
	HideVia bool `json:"hide_via,omitempty"`

	// If true, the strict check preventing HTTP upstreams will be disabled.
	DisableInsecureUpstreamsCheck bool `json:"disable_insecure_upstreams_check,omitempty"`

	// Host(s) (and ports) of the proxy. When you configure a client,
	// you will give it the host (and port) of the proxy to use.
	Hosts caddyhttp.MatchHost `json:"hosts,omitempty"`

	// Optional probe resistance. (See documentation.)
	ProbeResistance *ProbeResistance `json:"probe_resistance,omitempty"`

	// How long to wait before timing out initial TCP connections.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// Maximum number of idle connections to keep open, globally.
	// Default: 50. Set to -1 for no limit.
	// See https://pkg.go.dev/net/http#Transport.MaxIdleConns
	MaxIdleConns int `json:"max_idle_conns,omitempty"`

	// Maximum number of idle connections to keep open per host.
	// Default: 0, which uses Go's default of 2.
	// See https://pkg.go.dev/net/http#Transport.MaxIdleConnsPerHost
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`

	// Optionally configure an upstream proxy to use.
	Upstream string `json:"upstream,omitempty"`

	// Access control list.
	ACL []ACLRule `json:"acl,omitempty"`

	// Ports to be allowed to connect to (if non-empty).
	AllowedPorts []int `json:"allowed_ports,omitempty"`

	httpTransport *http.Transport

	// overridden dialContext allows us to redirect requests to upstream proxy
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
	upstream    *url.URL // address of upstream proxy

	aclRules []aclRule

	// TODO: temporary/deprecated - we should try to reuse existing authentication modules instead!
	AuthCredentials [][]byte `json:"auth_credentials,omitempty"` // slice with base64-encoded credentials

	// proxy UDP over http
	udpProxyServer udpProxyServer
	// Optionally configure a uri template for rfc 9298 to use.
	URITemplate string `json:"udp_uri_template,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision ensures that h is set up properly before use.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	if h.DialTimeout <= 0 {
		h.DialTimeout = caddy.Duration(30 * time.Second)
	}

	// Default to 50 max idle connections if not specified,
	// or no limit if -1 is specified.
	maxIdleConns := h.MaxIdleConns
	if maxIdleConns == 0 {
		maxIdleConns = 50
	}
	if maxIdleConns < 0 {
		maxIdleConns = 0
	}

	h.httpTransport = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: h.MaxIdleConnsPerHost,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// access control lists
	for _, rule := range h.ACL {
		for _, subj := range rule.Subjects {
			ar, err := newACLRule(subj, rule.Allow)
			if err != nil {
				return err
			}
			h.aclRules = append(h.aclRules, ar)
		}
	}
	for _, ipDeny := range []string{
		"10.0.0.0/8",
		"127.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fe80::/10",
	} {
		ar, err := newACLRule(ipDeny, false)
		if err != nil {
			return err
		}
		h.aclRules = append(h.aclRules, ar)
	}
	h.aclRules = append(h.aclRules, &aclAllRule{allow: true})

	if h.ProbeResistance != nil {
		if h.AuthCredentials == nil {
			return fmt.Errorf("probe resistance requires authentication")
		}
		if len(h.ProbeResistance.Domain) > 0 {
			h.logger.Info("Secret domain used to connect to proxy: " + h.ProbeResistance.Domain)
		}
	}

	dialer := &net.Dialer{
		Timeout:   time.Duration(h.DialTimeout),
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	h.dialContext = dialer.DialContext
	h.httpTransport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		return h.dialContextCheckACL(ctx, network, address)
	}

	if h.Upstream != "" {
		upstreamURL, err := url.Parse(h.Upstream)
		if err != nil {
			return fmt.Errorf("bad upstream URL: %v", err)
		}
		h.upstream = upstreamURL

		if !h.DisableInsecureUpstreamsCheck && !isLocalhost(h.upstream.Hostname()) && h.upstream.Scheme != "https" {
			return errors.New("insecure schemes are only allowed to localhost upstreams")
		}

		registerHTTPDialer := func(u *url.URL, _ proxy.Dialer) (proxy.Dialer, error) {
			// CONNECT request is proxied as-is, so we don't care about target url, but it could be
			// useful in future to implement policies of choosing between multiple upstream servers.
			// Given dialer is not used, since it's the same dialer provided by us.
			d, err := httpclient.NewHTTPConnectDialer(h.upstream.String())
			if err != nil {
				return nil, err
			}
			d.Dialer = *dialer
			if isLocalhost(h.upstream.Hostname()) && h.upstream.Scheme == "https" {
				// disabling verification helps with testing the package and setups
				// either way, it's impossible to have a legit TLS certificate for "127.0.0.1" - TODO: not true anymore
				h.logger.Info("Localhost upstream detected, disabling verification of TLS certificate")
				d.DialTLS = func(network string, address string) (net.Conn, string, error) {
					conn, err := tls.Dial(network, address, &tls.Config{InsecureSkipVerify: true}) // #nosec G402
					if err != nil {
						return nil, "", err
					}
					return conn, conn.ConnectionState().NegotiatedProtocol, nil
				}
			}
			return d, nil
		}
		proxy.RegisterDialerType("https", registerHTTPDialer)
		proxy.RegisterDialerType("http", registerHTTPDialer)

		upstreamDialer, err := proxy.FromURL(h.upstream, dialer)
		if err != nil {
			return errors.New("failed to create proxy to upstream: " + err.Error())
		}

		if ctxDialer, ok := upstreamDialer.(dialContexter); ok {
			// upstreamDialer has DialContext - use it
			h.dialContext = ctxDialer.DialContext
		} else {
			// upstreamDialer does not have DialContext - ignore the context :(
			h.dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
				return upstreamDialer.Dial(network, address)
			}
		}
	}

	// init masque proxy
	var err error
	h.udpProxyServer, err = newUDPProxyServer(h.URITemplate, h.logger)
	if err != nil {
		return fmt.Errorf("create udp proxy error: %w", err)
	}

	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// start by splitting the request host and port
	reqHost, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		reqHost = r.Host // OK; probably just didn't have a port
	}

	var authErr error
	if h.AuthCredentials != nil {
		authErr = h.checkCredentials(r)
	}
	if h.ProbeResistance != nil && len(h.ProbeResistance.Domain) > 0 && reqHost == h.ProbeResistance.Domain {
		return serveHiddenPage(w, authErr)
	}
	if h.Hosts.Match(r) && (r.Method != http.MethodConnect || authErr != nil) {
		// Always pass non-CONNECT requests to hostname
		// Pass CONNECT requests only if probe resistance is enabled and not authenticated
		if h.shouldServePACFile(r) {
			return h.servePacFile(w, r)
		}
		return next.ServeHTTP(w, r)
	}
	if authErr != nil {
		if h.ProbeResistance != nil {
			// probe resistance is requested and requested URI does not match secret domain;
			// act like this proxy handler doesn't even exist (pass thru to next handler)
			return next.ServeHTTP(w, r)
		}
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Caddy Secure Web Proxy\"")
		return caddyhttp.Error(http.StatusProxyAuthRequired, authErr)
	}

	if r.ProtoMajor != 1 && r.ProtoMajor != 2 && r.ProtoMajor != 3 {
		return caddyhttp.Error(http.StatusHTTPVersionNotSupported,
			fmt.Errorf("unsupported HTTP major version: %d", r.ProtoMajor))
	}

	ctx := context.Background()
	if !h.HideIP {
		ctxHeader := make(http.Header)
		for k, v := range r.Header {
			if kL := strings.ToLower(k); kL == "forwarded" || kL == "x-forwarded-for" {
				ctxHeader[k] = v
			}
		}
		ctxHeader.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
		ctx = context.WithValue(ctx, httpclient.ContextKeyHeader{}, ctxHeader)
	}

	// https://datatracker.ietf.org/doc/html/rfc9298
	// try UDP over HTTP
	isUDPoverHTTP, err := h.tryUDPoverHTTP(w, r)
	if isUDPoverHTTP {
		if err != nil {
			return fmt.Errorf("handle UDP over HTTP error: %w", err)
		}
		return nil
	}

	if r.Method == http.MethodConnect {
		if r.ProtoMajor == 2 || r.ProtoMajor == 3 {
			if len(r.URL.Scheme) > 0 || len(r.URL.Path) > 0 {
				return caddyhttp.Error(http.StatusBadRequest,
					fmt.Errorf("CONNECT request has :scheme and/or :path pseudo-header fields"))
			}
		}

		hostPort := r.URL.Host
		if hostPort == "" {
			hostPort = r.Host
		}
		targetConn, err := h.dialContextCheckACL(ctx, "tcp", hostPort)
		if err != nil {
			return err
		}
		if targetConn == nil {
			// safest to check both error and targetConn afterwards, in case fp.dial (potentially unstable
			// from x/net/proxy) misbehaves and returns both nil or both non-nil
			return caddyhttp.Error(http.StatusForbidden,
				fmt.Errorf("hostname %s is not allowed", r.URL.Hostname()))
		}
		defer targetConn.Close()

		switch r.ProtoMajor {
		case 1: // http1: hijack the whole flow
			return serveHijack(w, targetConn)
		case 2: // http2: keep reading from "request" and writing into same response
			fallthrough
		case 3:
			defer r.Body.Close()
			w.WriteHeader(http.StatusOK)
			err := http.NewResponseController(w).Flush()
			if err != nil {
				return caddyhttp.Error(http.StatusInternalServerError,
					fmt.Errorf("ResponseWriter flush error: %v", err))
			}
			return dualStream(targetConn, r.Body, w)
		}

		panic("There was a check for http version, yet it's incorrect")
	}

	// Scheme has to be appended to avoid `unsupported protocol scheme ""` error.
	// `http://` is used, since this initial request itself is always HTTP, regardless of what client and server
	// may speak afterwards.
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	r.Proto = "HTTP/1.1"
	r.ProtoMajor = 1
	r.ProtoMinor = 1
	r.RequestURI = ""

	removeHopByHop(r.Header)

	if !h.HideIP {
		r.Header.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
	}

	// https://tools.ietf.org/html/rfc7230#section-5.7.1
	if !h.HideVia {
		r.Header.Add("Via", strconv.Itoa(r.ProtoMajor)+"."+strconv.Itoa(r.ProtoMinor)+" caddy")
	}

	var response *http.Response
	if h.upstream == nil {
		// non-upstream request uses httpTransport to reuse connections
		if r.Body != nil &&
			(r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" || r.Method == "TRACE") {
			// make sure request is idempotent and could be retried by saving the Body
			// None of those methods are supposed to have body,
			// but we still need to copy the r.Body, even if it's empty
			rBodyBuf, err := io.ReadAll(r.Body)
			if err != nil {
				return caddyhttp.Error(http.StatusBadRequest,
					fmt.Errorf("failed to read request body: %v", err))
			}
			r.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(rBodyBuf)), nil
			}
			r.Body, _ = r.GetBody()
		}
		response, err = h.httpTransport.RoundTrip(r)
	} else {
		// Upstream requests don't interact well with Transport: connections could always be
		// reused, but Transport thinks they go to different Hosts, so it spawns tons of
		// useless connections.
		// Just use dialContext, which will multiplex via single connection, if http/2
		if creds := h.upstream.User.String(); creds != "" {
			// set upstream credentials for the request, if needed
			r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
		}
		if r.URL.Port() == "" {
			r.URL.Host = net.JoinHostPort(r.URL.Host, "80")
		}
		upsConn, err := h.dialContext(ctx, "tcp", r.URL.Host)
		if err != nil {
			return caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("failed to dial upstream: %v", err))
		}
		err = r.Write(upsConn)
		if err != nil {
			return caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("failed to write upstream request: %v", err))
		}
		response, err = http.ReadResponse(bufio.NewReader(upsConn), r)
		if err != nil {
			return caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("failed to read upstream response: %v", err))
		}
	}
	if err := r.Body.Close(); err != nil {
		return caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("failed to close response body: %v", err))
	}

	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if _, ok := err.(caddyhttp.HandlerError); ok {
			return err
		}
		return caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("failed to read response: %v", err))
	}

	return forwardResponse(w, response)
}

func (h Handler) checkCredentials(r *http.Request) error {
	pa := strings.Split(r.Header.Get("Proxy-Authorization"), " ")
	if len(pa) != 2 {
		return errors.New("Proxy-Authorization is required! Expected format: <type> <credentials>")
	}
	if strings.ToLower(pa[0]) != "basic" {
		return errors.New("auth type is not supported")
	}
	for _, creds := range h.AuthCredentials {
		if subtle.ConstantTimeCompare(creds, []byte(pa[1])) == 1 {
			repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
			buf := make([]byte, base64.StdEncoding.DecodedLen(len(creds)))
			_, _ = base64.StdEncoding.Decode(buf, creds) // should not err ever since we are decoding a known good input
			cred := string(buf)
			repl.Set("http.auth.user.id", cred[:strings.IndexByte(cred, ':')])
			// Please do not consider this to be timing-attack-safe code. Simple equality is almost
			// mindlessly substituted with constant time algo and there ARE known issues with this code,
			// e.g. size of smallest credentials is guessable. TODO: protect from all the attacks! Hash?
			return nil
		}
	}
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	buf := make([]byte, base64.StdEncoding.DecodedLen(len([]byte(pa[1]))))
	n, err := base64.StdEncoding.Decode(buf, []byte(pa[1]))
	if err != nil {
		repl.Set("http.auth.user.id", "invalidbase64:"+err.Error())
		return err
	}
	if utf8.Valid(buf[:n]) {
		cred := string(buf[:n])
		i := strings.IndexByte(cred, ':')
		if i >= 0 {
			repl.Set("http.auth.user.id", "invalid:"+cred[:i])
		} else {
			repl.Set("http.auth.user.id", "invalidformat:"+cred)
		}
	} else {
		repl.Set("http.auth.user.id", "invalid::")
	}
	return errors.New("invalid credentials")
}

func (h Handler) shouldServePACFile(r *http.Request) bool {
	return len(h.PACPath) > 0 && r.URL.Path == h.PACPath
}

func (h Handler) servePacFile(w http.ResponseWriter, r *http.Request) error {
	fmt.Fprintf(w, pacFile, r.Host)
	// fmt.Fprintf(w, pacFile, h.hostname, h.port)
	return nil
}

// dialContextCheckACL enforces Access Control List and calls fp.DialContext
func (h Handler) dialContextCheckACL(ctx context.Context, network, hostPort string) (net.Conn, error) {
	var conn net.Conn

	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		// return nil, &proxyError{S: "Network " + network + " is not supported", Code: http.StatusBadRequest}
		return nil, caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("network %s is not supported", network))
	}

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		// return nil, &proxyError{S: err.Error(), Code: http.StatusBadRequest}
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	if h.upstream != nil {
		// if upstreaming -- do not resolve locally nor check acl
		conn, err = h.dialContext(ctx, network, hostPort)
		if err != nil {
			// return conn, &proxyError{S: err.Error(), Code: http.StatusBadGateway}
			return conn, caddyhttp.Error(http.StatusBadGateway, err)
		}
		return conn, nil
	}

	if !h.portIsAllowed(port) {
		// return nil, &proxyError{S: "port " + port + " is not allowed", Code: http.StatusForbidden}
		return nil, caddyhttp.Error(http.StatusForbidden,
			fmt.Errorf("port %s is not allowed", port))
	}

match:
	for _, rule := range h.aclRules {
		if _, ok := rule.(*aclDomainRule); ok {
			switch rule.tryMatch(nil, host) {
			case aclDecisionDeny:
				return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("disallowed host %s", host))
			case aclDecisionAllow:
				break match
			}
		}
	}

	// in case IP was provided, net.LookupIP will simply return it
	IPs, err := net.LookupIP(host)
	if err != nil {
		// return nil, &proxyError{S: fmt.Sprintf("Lookup of %s failed: %v", host, err),
		// Code: http.StatusBadGateway}
		return nil, caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("lookup of %s failed: %v", host, err))
	}

	// This is net.Dial's default behavior: if the host resolves to multiple IP addresses,
	// Dial will try each IP address in order until one succeeds
	for _, ip := range IPs {
		if !h.hostIsAllowed(host, ip) {
			continue
		}

		conn, err = h.dialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}

	return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("no allowed IP addresses for %s", host))
}

func (h Handler) hostIsAllowed(hostname string, ip net.IP) bool {
	for _, rule := range h.aclRules {
		switch rule.tryMatch(ip, hostname) {
		case aclDecisionDeny:
			return false
		case aclDecisionAllow:
			return true
		}
	}
	// TODO: convert this to log entry
	// fmt.Println("ERROR: no acl match for ", hostname, ip) // shouldn't happen
	return false
}

func (h Handler) portIsAllowed(port string) bool {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if portInt <= 0 || portInt > 65535 {
		return false
	}
	if len(h.AllowedPorts) == 0 {
		return true
	}
	isAllowed := false
	for _, p := range h.AllowedPorts {
		if p == portInt {
			isAllowed = true
			break
		}
	}
	return isAllowed
}

func serveHiddenPage(w http.ResponseWriter, authErr error) error {
	const hiddenPage = `<html>
<head>
  <title>Hidden Proxy Page</title>
</head>
<body>
<h1>Hidden Proxy Page!</h1>
%s<br/>
</body>
</html>`
	const AuthFail = "Please authenticate yourself to the proxy."
	const AuthOk = "Congratulations, you are successfully authenticated to the proxy! Go browse all the things!"

	w.Header().Set("Content-Type", "text/html")
	if authErr != nil {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Caddy Secure Web Proxy\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		_, _ = w.Write([]byte(fmt.Sprintf(hiddenPage, AuthFail)))
		return authErr
	}
	_, _ = w.Write([]byte(fmt.Sprintf(hiddenPage, AuthOk)))
	return nil
}

// Hijacks the connection from ResponseWriter, writes the response and proxies data between targetConn
// and hijacked connection.
func serveHijack(w http.ResponseWriter, targetConn net.Conn) error {
	w.WriteHeader(http.StatusOK)
	clientConn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("hijack failed: %v", err))
	}
	defer clientConn.Close()
	// bufReader may contain unprocessed buffered data from the client.
	// snippet borrowed from `proxy` plugin
	if n := brw.Reader.Buffered(); n > 0 {
		rbuf, _ := brw.Peek(n)
		_, _ = targetConn.Write(rbuf)
	}
	err = brw.Flush()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("failed to flush to client: %v", err))
	}

	return dualStream(targetConn, clientConn, clientConn)
}

// Copies data target->clientReader and clientWriter->target, and flushes as needed
// Returns when clientWriter-> target stream is done.
// Caddy should finish writing target -> clientReader.
func dualStream(target net.Conn, clientReader io.ReadCloser, clientWriter io.Writer) error {
	stream := func(w io.Writer, r io.Reader) error {
		// copy bytes from r to w
		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		buf = buf[0:cap(buf)]
		_, _err := flushingIoCopy(w, r, buf)
		bufferPool.Put(bufPtr)

		if cw, ok := w.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		return _err
	}
	go stream(target, clientReader) //nolint: errcheck
	return stream(clientWriter, target)
}

type closeWriter interface {
	CloseWrite() error
}

// flushingIoCopy is analogous to buffering io.Copy(), but also attempts to flush on each iteration.
// If dst does not implement http.Flusher(e.g. net.TCPConn), it will do a simple io.CopyBuffer().
// Reasoning: http2ResponseWriter will not flush on its own, so we have to do it manually.
func flushingIoCopy(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	rw, ok := dst.(http.ResponseWriter)
	if !ok {
		return io.CopyBuffer(dst, src, buf)
	}
	rc := http.NewResponseController(rw)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			ef := rc.Flush()
			if ef != nil {
				err = ef
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

// Removes hop-by-hop headers, and writes response into ResponseWriter.
func forwardResponse(w http.ResponseWriter, response *http.Response) error {
	w.Header().Del("Server") // remove Server: Caddy, append via instead
	w.Header().Add("Via", strconv.Itoa(response.ProtoMajor)+"."+strconv.Itoa(response.ProtoMinor)+" caddy")

	for header, values := range response.Header {
		for _, val := range values {
			w.Header().Add(header, val)
		}
	}
	removeHopByHop(w.Header())
	w.WriteHeader(response.StatusCode)
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	buf = buf[0:cap(buf)]
	_, err := io.CopyBuffer(w, response.Body, buf)
	bufferPool.Put(bufPtr)
	return err
}

func removeHopByHop(header http.Header) {
	connectionHeaders := header.Get("Connection")
	for _, h := range strings.Split(connectionHeaders, ",") {
		header.Del(strings.TrimSpace(h))
	}
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

var hopByHopHeaders = []string{
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Upgrade",
	"Connection",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
}

const pacFile = `
function FindProxyForURL(url, host) {
	if (host === "127.0.0.1" || host === "::1" || host === "localhost")
		return "DIRECT";
	return "HTTPS %s";
}
`

var bufferPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, 0, 32*1024)
		return &buffer
	},
}

////// used during provision only

func isLocalhost(hostname string) bool {
	return hostname == "localhost" ||
		hostname == "127.0.0.1" ||
		hostname == "::1"
}

type dialContexter interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ProbeResistance configures probe resistance.
type ProbeResistance struct {
	Domain string `json:"domain,omitempty"`
}

func readLinesFromFile(filename string) ([]string, error) {
	cleanFilename := filepath.Clean(filename)
	file, err := os.Open(cleanFilename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hostnames []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hostnames = append(hostnames, scanner.Text())
	}

	return hostnames, scanner.Err()
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)

const (
	RequestProtocol = "connect-udp"

	ConnectUDPBindHeader     = "Connect-Udp-Bind"
	ProxyPublicAddressHeader = "Proxy-Public-Address"

	CompressionAssignValue = 0x1C0FE323
	CompressionCloseValue  = 0x1C0FE324
)

var (
	CapsuleProtocolHeaderValue string
	ConnectUDPBindHeaderValue  string
)

func init() {
	str, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	CapsuleProtocolHeaderValue = str
	ConnectUDPBindHeaderValue = str
}

type Payload interface {
	Len() uint64
	Parse([]byte) error
	Send(io.Writer) error
}

type Datagram struct {
	Type    uint64
	Length  uint64
	Payload Payload
}

func (data *Datagram) Receive(r io.Reader) error {
	return data.ReceiveBuffer(r, make([]byte, 1024*32))
}

func (data *Datagram) ReceiveBuffer(r io.Reader, b []byte) error {
	err := error(nil)

	rr := quicvarint.NewReader(r)
	data.Type, err = quicvarint.Read(rr)
	if err != nil {
		return fmt.Errorf("receive datagram type error: %w", err)
	}

	data.Length, err = quicvarint.Read(rr)
	if err != nil {
		return fmt.Errorf("receive datagram length error: %w", err)
	}

	bb := b[:data.Length]
	_, err = io.ReadFull(r, bb)
	if err != nil {
		return fmt.Errorf("receive datagram payload error: %w", err)
	}

	data.Payload = &BytePayload{Payload: bb}

	return nil
}

func (data *Datagram) Send(w io.Writer) error {
	bb := quicvarint.Append(quicvarint.Append(make([]byte, 0, 16), data.Type), data.Length)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send type, length error: %w", err)
	}

	err = data.Payload.Send(w)
	if err != nil {
		return fmt.Errorf("send UDP payload error: %w", err)
	}

	return nil
}

type BytePayload struct {
	Payload []byte
}

func (data *BytePayload) Send(w io.Writer) error {
	_, err := w.Write(data.Payload)
	return err
}

func (data *BytePayload) Len() uint64 {
	return uint64(len(data.Payload))
}

func (data *BytePayload) Parse(b []byte) error {
	data.Payload = b
	return nil
}

type CompressedPayload struct {
	ContextID uint64
	Payload   []byte
}

func (data *CompressedPayload) Send(w io.Writer) error {
	bb := quicvarint.Append(make([]byte, 0, 8), data.ContextID)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send context id error: %w", err)
	}

	_, err = w.Write(data.Payload)
	if err != nil {
		return fmt.Errorf("send payload error: %w", err)
	}
	return nil
}

func (data *CompressedPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}
	data.ContextID = id
	data.Payload = b[nr:]
	return nil
}

func (data *CompressedPayload) Len() uint64 {
	return uint64(quicvarint.Len(data.ContextID)) + uint64(len(data.Payload))
}

type UncompressedPayload struct {
	ContextID uint64
	IPVersion uint8
	Addr      netip.Addr
	Port      uint16
	Payload   []byte
}

func (data *UncompressedPayload) Send(w io.Writer) error {
	bb := append(append(append(quicvarint.Append(make([]byte, 0, 32), data.ContextID), byte(data.IPVersion)),
		data.Addr.AsSlice()...), byte(data.Port>>8), byte(data.Port))
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send uncompressed payload header error: %w", err)
	}

	_, err = w.Write(data.Payload)
	if err != nil {
		return fmt.Errorf("send payload error: %w", err)
	}
	return nil
}

func (data *UncompressedPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}

	data.ContextID = id

	switch b[nr] { // IPVersion
	case 4:
		data.IPVersion = 4
		data.Addr = netip.AddrFrom4([4]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4]})
		data.Port = uint16(b[nr+5])<<8 | uint16(b[nr+6])
		data.Payload = b[nr+7:]
	case 6:
		data.IPVersion = 6
		data.Addr = netip.AddrFrom16(
			[16]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4],
				b[nr+5], b[nr+6], b[nr+7], b[nr+8],
				b[nr+9], b[nr+10], b[nr+11], b[nr+12],
				b[nr+13], b[nr+14], b[nr+15], b[nr+16]})
		data.Port = uint16(b[nr+17])<<8 | uint16(b[nr+18])
		data.Payload = b[nr+19:]
	default:
		return fmt.Errorf("not a valid IP version: %v", b[nr])
	}
	return nil
}

func (data *UncompressedPayload) Len() uint64 {
	switch data.IPVersion {
	case 4:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 4 + 2 + uint64(len(data.Payload))
	case 6:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 16 + 2 + uint64(len(data.Payload))
	}
	return 0
}

type CompressionAssignPayload struct {
	ContextID uint64
	IPVersion uint8
	Addr      netip.Addr
	Port      uint16
}

func (data *CompressionAssignPayload) Send(w io.Writer) error {
	bb := append(quicvarint.Append(make([]byte, 0, 32), data.ContextID), byte(data.IPVersion))
	if data.IPVersion != 0 {
		bb = append(append(bb, data.Addr.AsSlice()...), byte(data.Port>>8), byte(data.Port))
	}

	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send compression assign payload header error: %w", err)
	}

	return nil
}

func (data *CompressionAssignPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}

	data.ContextID = id

	switch b[nr] { // IPVersion
	case 0:
		data.IPVersion = 0
	case 4:
		data.IPVersion = 4
		data.Addr = netip.AddrFrom4([4]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4]})
		data.Port = uint16(b[nr+5])<<8 | uint16(b[nr+6])
	case 6:
		data.IPVersion = 6
		data.Addr = netip.AddrFrom16(
			[16]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4],
				b[nr+5], b[nr+6], b[nr+7], b[nr+8],
				b[nr+9], b[nr+10], b[nr+11], b[nr+12],
				b[nr+13], b[nr+14], b[nr+15], b[nr+16]})
		data.Port = uint16(b[nr+17])<<8 | uint16(b[nr+18])
	default:
		return fmt.Errorf("not a valid IP version: %v", b[nr])
	}
	return nil
}

func (data *CompressionAssignPayload) Len() uint64 {
	switch data.IPVersion {
	case 0:
		// context id is 2
		return 1 + 1
	case 4:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 4 + 2
	case 6:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 16 + 2
	}
	return 0
}

type CompressionClosePayload struct {
	ContextID uint64
}

func (data *CompressionClosePayload) Send(w io.Writer) error {
	bb := quicvarint.Append(make([]byte, 0, 8), data.ContextID)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send context id error: %w", err)
	}
	return nil
}

func (data *CompressionClosePayload) Parse(b []byte) error {
	var err error
	data.ContextID, _, err = quicvarint.Parse(b)
	if err != nil {
		return fmt.Errorf("parse context id error: %v", err)
	}
	return nil
}

func (data *CompressionClosePayload) Len() uint64 {
	return uint64(quicvarint.Len(data.ContextID))
}

type PacketConn struct {
	DatagramSender
	Conn       io.Reader
	ContextID  uint64
	ContextMap struct {
		sync.RWMutex
		Map map[uint64]netip.AddrPort
	}
	AddrMap struct {
		sync.RWMutex
		Map map[netip.AddrPort]uint64
	}

	firewall atomic.Bool
}

func newPacketConn(rw io.ReadWriter) *PacketConn {
	nm := PacketConn{
		DatagramSender: DatagramSender{
			w: rw,
		},
		Conn:      rw,
		ContextID: 1,
	}
	nm.ContextMap.Map = map[uint64]netip.AddrPort{}
	nm.AddrMap.Map = map[netip.AddrPort]uint64{}
	return &nm
}

func (nm *PacketConn) GetAddr(id uint64) (netip.AddrPort, bool) {
	nm.ContextMap.RLock()
	addr, ok := nm.ContextMap.Map[id]
	nm.ContextMap.RUnlock()
	return addr, ok
}

func (nm *PacketConn) GetContextID(addr netip.AddrPort) (uint64, bool) {
	nm.AddrMap.RLock()
	id, ok := nm.AddrMap.Map[addr]
	nm.AddrMap.RUnlock()
	return id, ok
}

func (nm *PacketConn) Add(id uint64, addr netip.AddrPort) {
	nm.ContextMap.Lock()
	nm.AddrMap.Lock()
	nm.ContextMap.Map[id] = addr
	nm.AddrMap.Map[addr] = id
	nm.AddrMap.Unlock()
	nm.ContextMap.Unlock()
}

func (nm *PacketConn) Del(id uint64) {
	nm.ContextMap.Lock()
	addr, ok := nm.ContextMap.Map[id]
	delete(nm.ContextMap.Map, id)
	if ok {
		nm.AddrMap.Lock()
		delete(nm.AddrMap.Map, addr)
		nm.AddrMap.Unlock()
	}
	nm.ContextMap.Unlock()
}

func (pc *PacketConn) WritePacket(b []byte, addr netip.AddrPort) error {
	id, ok := pc.GetContextID(addr)
	if !ok {
		if pc.Firewall() {
			return nil
		}

		pc.ContextID += 2 // odd context id for server side compression assign
		id = pc.ContextID

		// send compression assign to utlize compressed payload
		data := Datagram{
			Type: CompressionAssignValue,
		}
		pl := CompressionAssignPayload{}
		pl.ContextID = id
		if naddr := addr.Addr(); naddr.Is4() {
			pl.IPVersion = 4
			pl.Addr = naddr
		} else {
			pl.IPVersion = 6
			pl.Addr = naddr
		}
		pl.Port = addr.Port()
		data.Length = pl.Len()
		data.Payload = &pl

		err := pc.SendDatagram(data)
		if err != nil {
			return err
		}

		pc.Add(id, netip.AddrPortFrom(pl.Addr, pl.Port))
	}

	data := Datagram{
		Type: 0,
	}
	pl := &CompressedPayload{
		ContextID: id,
		Payload:   b,
	}
	data.Length = pl.Len()
	data.Payload = pl

	return pc.SendDatagram(data)
}

func (nm *PacketConn) ReadPacket(b []byte) ([]byte, netip.AddrPort, error) {
	data := Datagram{}

	for {
		err := data.ReceiveBuffer(nm.Conn, b)
		if err != nil {
			return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
		}

		bb := (data.Payload.(*BytePayload)).Payload
		switch data.Type {
		case 0:
			// slog.Info("receive new UDP datagram")
			id, nr, err := quicvarint.Parse(bb)
			if err != nil {
				return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
			}

			if id == 2 {
				if nm.Firewall() {
					// ignore all packets with conext id set as 2 when assign close is set
					continue
				}
				switch bb[1] {
				case 4:
					// nr = 1
					return bb[8:], netip.AddrPortFrom(netip.AddrFrom4(
						[4]byte{bb[2], bb[3], bb[4], bb[5]}), uint16(bb[6])<<8|uint16(bb[7])), nil
				case 6:
					// nr = 1
					return bb[20:], netip.AddrPortFrom(netip.AddrFrom16(
						[16]byte{bb[2], bb[3], bb[4], bb[5],
							bb[6], bb[7], bb[8], bb[9],
							bb[10], bb[11], bb[12], bb[13],
							bb[14], bb[15], bb[16], bb[17]}), uint16(bb[18])<<8|uint16(bb[19])), nil
				default:
					return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), fmt.Errorf("ip version error: %v", bb[1])
				}
			}

			addr, ok := nm.GetAddr(id)
			if ok {
				return bb[nr:], addr, nil
			}
		case CompressionAssignValue:
			// slog.Info("receive new compression assign datagram")
			data := Datagram{
				Type: CompressionAssignValue,
			}
			pl := CompressionAssignPayload{}
			if err := pl.Parse(bb); err != nil {
				return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
			}
			data.Length = pl.Len()
			data.Payload = &pl

			// even for client side, odd for server side
			// ignore all odd id
			if pl.ContextID&1 == 0 {
				switch pl.IPVersion {
				case 0:
					if pl.ContextID != 2 {
						// use 2 for default uncompressed context id
						continue
					}

					nm.SetFirewall(false)
				case 4:
					nm.Add(pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port))
				case 6:
					nm.Add(pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port))
				default:
					return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), fmt.Errorf("ip version error: %v", bb[1])
				}

				err := nm.SendDatagram(data)
				if err != nil {
					return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
				}
			}
		case CompressionCloseValue:
			data := Datagram{
				Type: CompressionCloseValue,
			}
			pl := CompressionClosePayload{}
			err = pl.Parse(bb)
			if err != nil {
				return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
			}
			data.Length = pl.Len()
			data.Payload = &pl

			if pl.ContextID&1 == 0 {
				if pl.ContextID == 2 {
					nm.SetFirewall(true)
				} else {
					nm.Del(pl.ContextID)
				}

				err = nm.SendDatagram(data)
				if err != nil {
					return nil, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), err
				}
			}
		default:
			continue
		}
	}
}

func (nm *PacketConn) Firewall() bool {
	return nm.firewall.Load()
}

func (nm *PacketConn) SetFirewall(ok bool) {
	nm.firewall.Store(ok)
}

type Request string

type RequestMatcher struct {
	source       string
	tokens       []string
	patternRegex *regexp.Regexp
}

func (rm *RequestMatcher) Create(source string) error {
	const tempToken = "__TMPTKN__"

	delimiters := []rune{'{', '}'}

	tokenRegex := regexp.MustCompile(string(delimiters[0]) + "([^" + string(delimiters) + "\\t\\r\\n]+)" + string(delimiters[1]))
	tokenMatches := tokenRegex.FindAllStringSubmatch(source, -1)
	tokens := make([]string, len(tokenMatches))
	for i, v := range tokenMatches {
		tokens[i] = v[1] //Index 1 is the first (and only) submatch
	}

	substitutedTemplate := tokenRegex.ReplaceAllString(source, tempToken) // Substitution is required before escaping so that the capture group doesn't get escaped
	escapedSubstitutedTemplate := regexp.QuoteMeta(substitutedTemplate)
	escapedTemplate := strings.ReplaceAll(escapedSubstitutedTemplate, tempToken, "(.+)")
	patternRegex, err := regexp.Compile(escapedTemplate)
	if err != nil {
		return fmt.Errorf("error when constructing regex: %v", err)
	}

	rm.source = source
	rm.tokens = tokens
	rm.patternRegex = patternRegex
	return nil
}

// Provided an input and a template, returns a map of tokens to values
func (rm RequestMatcher) Extract(input string) (map[string]string, error) {
	var ErrNoMatch = errors.New("unable to match")

	matches := rm.patternRegex.FindStringSubmatch(input)
	if len(matches) != len(rm.tokens)+1 {
		return nil, ErrNoMatch
	}

	result := make(map[string]string)
	for i, v := range rm.tokens {
		result[v] = matches[i+1]
	}

	return result, nil
}

type DatagramSender struct {
	sync.Mutex
	w io.Writer
}

func (ds *DatagramSender) SendDatagram(data Datagram) error {
	ds.Lock()
	err := data.Send(ds.w)
	ds.Unlock()
	return err
}

type udpProxyServer struct {
	*zap.Logger
	Matcher RequestMatcher
}

func newUDPProxyServer(uri string, lg *zap.Logger) (udpProxyServer, error) {
	srv := udpProxyServer{Logger: lg}
	if uri == "" {
		// CONNECT https://{host}/.well-known/masque/udp/{target_host}/{target_port}/
		// GET /.well-known/masque/udp/{target_host}/{target_port}/
		uri = "https://{host}/.well-known/masque/udp/{target_host}/{target_port}/"
	}
	err := srv.Matcher.Create(uri)
	if err != nil {
		return srv, fmt.Errorf("parse uri template error: %w", err)
	}
	return srv, err
}

func (srv udpProxyServer) HandleStream(c io.ReadWriter, req Request, rc *net.UDPConn) error {
	if req == "*" {
		return srv.HandleStreamBind(c, req, rc)
	}

	done := make(chan struct{})

	go func() {
		b := make([]byte, 2048)
		for {
			data := Datagram{}
			err := data.ReceiveBuffer(c, b)
			if err != nil {
				break
			}

			if data.Type != 0 {
				continue
			}

			pl := &CompressedPayload{}
			err = pl.Parse((data.Payload.(*BytePayload)).Payload)
			if err != nil {
				break
			}

			if pl.ContextID != 0 {
				continue
			}

			_, err = rc.Write(pl.Payload)
			if err != nil {
				break
			}
		}

		rc.Close()
		done <- struct{}{}
	}()

	b := make([]byte, 2048)
	for {
		nr, err := rc.Read(b)
		if err != nil {
			break
		}

		data := Datagram{
			Type: 0,
		}
		pl := &CompressedPayload{
			ContextID: 0,
			Payload:   b[:nr],
		}

		// data.Length = quicvarint.Len(0) + uint64(nr)
		data.Length = 1 + uint64(nr)
		data.Payload = pl

		err = data.Send(c)
		if err != nil {
			break
		}
	}

	<-done
	return nil
}

func (srv udpProxyServer) HandleStreamBind(c io.ReadWriter, req Request, rc *net.UDPConn) error {
	pc := newPacketConn(c)

	done := make(chan struct{})

	go func() {
		bb := make([]byte, 2048)
		for {
			pkt, addr, err := pc.ReadPacket(bb)
			if err != nil {
				break
			}
			// slog.Info("receive new datagram")

			_, err = rc.WriteToUDPAddrPort(pkt, addr)
			if err != nil {
				break
			}
		}

		rc.Close()
		done <- struct{}{}
	}()

	bb := make([]byte, 2048)
	for {
		nr, addr, err := rc.ReadFromUDPAddrPort(bb)
		if err != nil {
			break
		}

		if addr.Addr().Is4In6() {
			addr = netip.AddrPortFrom(netip.AddrFrom4(addr.Addr().As4()), addr.Port())
		}

		err = pc.WritePacket(bb[:nr], addr)
		if err != nil {
			break
		}
	}

	<-done
	return nil
}

func (srv udpProxyServer) HandlePacket(str http3.Stream, req Request, rc *net.UDPConn) error {
	// https://github.com/quic-go/masque-go/issues/64
	if req == "*" {
		return srv.HandlePacketBind(str, req, rc)
	}

	// https://github.com/quic-go/masque-go/blob/master/proxy.go
	done := make(chan struct{})

	go func() {
		for {
			data, err := str.ReceiveDatagram(context.Background())
			if err != nil {
				break
			}
			id, nr, err := quicvarint.Parse(data)
			if err != nil {
				break
			}
			if id != 0 {
				// Drop this datagram. We currently only support proxying of UDP payloads.
				continue
			}
			if _, err := rc.Write(data[nr:]); err != nil {
				break
			}
		}

		rc.Close()
		done <- struct{}{}
	}()

	go func() {
		b := make([]byte, 2048)
		for {
			nr, err := rc.Read(b[1:])
			if err != nil {
				break
			}

			// context id is always 0
			if err := str.SendDatagram(b[:nr+1]); err != nil {
				break
			}
		}

		done <- struct{}{}
	}()

	// discard all capsules sent on the request stream
	if err := func(str quicvarint.Reader) error {
		for {
			_, r, err := http3.ParseCapsule(str)
			if err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, r); err != nil {
				return err
			}
		}
	}(quicvarint.NewReader(&str)); errors.Is(err, io.EOF) {
	}

	<-done
	<-done
	return nil
}

func (srv udpProxyServer) HandlePacketBind(str http3.Stream, req Request, c *net.UDPConn) error {
	return fmt.Errorf("connect-udp-bind over http3 is not supported yet")
}

func (srv udpProxyServer) ParseRequest(r *http.Request) (Request, error) {
	switch r.ProtoMajor {
	case 1:
		// parse HTTP/1.1 request
		if r.Method != http.MethodGet {
			return "", fmt.Errorf("expected GET request, got %s", r.Method)
		}
		if hdr := r.Header.Get("Connection"); hdr != "Upgrade" {
			return "", fmt.Errorf("unexpected Connection: %s", hdr)
		}
		if hdr := r.Header.Get("Upgrade"); hdr != RequestProtocol {
			return "", fmt.Errorf("unexpected Upgrade: %s", hdr)
		}
	case 2:
		// copy from https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/reverseproxy/reverseproxy.go#L414-L428
		// check HTTP2 request
		if r.Method != http.MethodConnect {
			return "", fmt.Errorf("expected CONNECT request, got %s", r.Method)
		}
		if hdr := r.Header.Get(":protocol"); hdr != RequestProtocol {
			return "", fmt.Errorf("unexpected protocol: %s", hdr)
		}
	case 3:
		// copy from https://github.com/quic-go/masque-go/blob/master/request.go#L47-L119
		// and remove ckecking host
		if r.Method != http.MethodConnect {
			return "", fmt.Errorf("expected CONNECT request, got %s", r.Method)
		}
		if r.Proto != RequestProtocol {
			return "", fmt.Errorf("unexpected protocol: %s", r.Proto)
		}
	default:
		return "", fmt.Errorf("unexpected HTTP version: %v", r.ProtoMajor)
	}

	// The capsule protocol header is optional, but if it's present,
	// we need to validate its value
	if values, ok := r.Header[http3.CapsuleProtocolHeader]; ok {
		item, err := httpsfv.UnmarshalItem(values)
		if err != nil {
			return "", fmt.Errorf("invalid capsule header value: %s", values)
		}
		if v, ok := item.Value.(bool); !ok {
			return "", fmt.Errorf("incorrect capsule header value type: %s", reflect.TypeOf(item.Value))
		} else if !v {
			return "", fmt.Errorf("incorrect capsule header value: %t", item.Value)
		}
	}

	// check request as UDP bind
	var isUDPBind bool
	if values, ok := r.Header[ConnectUDPBindHeader]; ok {
		item, err := httpsfv.UnmarshalItem(values)
		if err != nil {
			return "", fmt.Errorf("invalid bind header value: %s", values)
		}
		if v, ok := item.Value.(bool); !ok {
			return "", fmt.Errorf("incorrect connect udp bind header value type: %s", reflect.TypeOf(item.Value))
		} else if !v {
			return "", fmt.Errorf("incorrect connect udp bind header value: %t", item.Value)
		}
		isUDPBind = true
	}

	match, err := func() (map[string]string, error) {
		uri := *r.URL
		if uri.Scheme == "" {
			uri.Scheme = "https"
		}
		if uri.Host == "" {
			uri.Host = "in-place.com"
		}
		return srv.Matcher.Extract(uri.String())
	}()
	if err != nil {
		return "", fmt.Errorf("extract uri from %s error: %w", r.URL.String(), err)
	}

	targetHost := func(s string) string { return strings.ReplaceAll(s, "%3A", ":") }(match["target_host"])
	targetPortStr := match["target_port"]
	if targetHost == "" || targetPortStr == "" {
		return "", fmt.Errorf("expected target_host and target_port")
	}
	if targetHost == "*" && targetPortStr == "*" {
		if isUDPBind {
			return "*", nil
		}
		return "", fmt.Errorf("invalid Connect-UDP-Bind: %v", r.Header[ConnectUDPBindHeader])
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode target_port: %w", err)
	}
	return Request(net.JoinHostPort(targetHost, strconv.Itoa(targetPort))), nil
}

func (h Handler) tryUDPoverHTTP(w http.ResponseWriter, r *http.Request) (bool, error) {
	// slog.Info("try UDP over HTTP")
	// do not handle UDP over HTTP if upstream is set
	if h.upstream != nil {
		// slog.Info(fmt.Sprintf("use upstream: %s", h.Upstream))
		return false, nil
	}

	// parse request
	req, err := h.udpProxyServer.ParseRequest(r)
	if err != nil {
		// slog.Error(fmt.Sprintf("parse request: %s", err.Error()))
		return false, err
	}

	// slog.Info(fmt.Sprintf("handle UDP over HTTP request: ---> %s", req))

	var rconn *net.UDPConn
	if req == "*" {
		err := error(nil)
		rconn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return false, fmt.Errorf("listen UDP connection error: %w", err)
		}
		defer rconn.Close()
	} else {
		ok, err := func(hostPort string) (bool, error) {
			host, port, err := net.SplitHostPort(hostPort)
			if err != nil {
				// return nil, &proxyError{S: err.Error(), Code: http.StatusBadRequest}
				return false, caddyhttp.Error(http.StatusBadRequest, err)
			}

			if !h.portIsAllowed(port) {
				// return nil, &proxyError{S: "port " + port + " is not allowed", Code: http.StatusForbidden}
				return false, caddyhttp.Error(http.StatusForbidden,
					fmt.Errorf("port %s is not allowed", port))
			}

		match:
			for _, rule := range h.aclRules {
				if _, ok := rule.(*aclDomainRule); ok {
					switch rule.tryMatch(nil, host) {
					case aclDecisionDeny:
						return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("disallowed host %s", host))
					case aclDecisionAllow:
						break match
					}
				}
			}

			// in case IP was provided, net.LookupIP will simply return it
			IPs, err := net.LookupIP(host)
			if err != nil {
				// return nil, &proxyError{S: fmt.Sprintf("Lookup of %s failed: %v", host, err),
				// Code: http.StatusBadGateway}
				return false, caddyhttp.Error(http.StatusBadGateway,
					fmt.Errorf("lookup of %s failed: %v", host, err))
			}

			// This is net.Dial's default behavior: if the host resolves to multiple IP addresses,
			// Dial will try each IP address in order until one succeeds
			for _, ip := range IPs {
				if !h.hostIsAllowed(host, ip) {
					continue
				}
				return true, nil
			}

			return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("no allowed IP addresses for %s", host))
		}(string(req))
		if !ok {
			return false, err
		}

		raddr, err := net.ResolveUDPAddr("udp", string(req))
		if err != nil {
			return false, fmt.Errorf("resolve UDP address error: %w", err)
		}

		rconn, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			return false, fmt.Errorf("dial UDP connection error: %w", err)
		}
		defer rconn.Close()
	}

	switch r.ProtoMajor {
	case 1:
		// slog.Info(fmt.Sprintf("handle UDP over HTTP/1.1 request: ---> %s", req))

		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade:", RequestProtocol)
		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
		if req == "*" {
			w.Header().Set(ConnectUDPBindHeader, ConnectUDPBindHeaderValue)
			w.Header().Set(ProxyPublicAddressHeader, rconn.LocalAddr().String())
		}
		w.WriteHeader(http.StatusSwitchingProtocols)

		rc := http.NewResponseController(w)
		err = rc.Flush()
		if err != nil {
			return true, caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("ResponseWriter flush error: %v", err))
		}

		conn, _, err := rc.Hijack()
		if err != nil {
			return true, err
		}
		defer conn.Close()

		return true, h.udpProxyServer.HandleStream(conn, req, rconn)
	case 2:
		// slog.Info(fmt.Sprintf("handle UDP over HTTP/2.0 request: ---> %s", req))

		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
		if req == "*" {
			w.Header().Set(ConnectUDPBindHeader, ConnectUDPBindHeaderValue)
			w.Header().Set(ProxyPublicAddressHeader, rconn.LocalAddr().String())
		}
		w.WriteHeader(http.StatusOK)

		rc := http.NewResponseController(w)
		err = rc.Flush()
		if err != nil {
			return true, caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("ResponseWriter flush error: %v", err))
		}

		conn, _, err := rc.Hijack()
		if err != nil {
			return true, err
		}
		defer conn.Close()

		return true, h.udpProxyServer.HandleStream(conn, req, rconn)
	case 3:
		// slog.Info(fmt.Sprintf("handle UDP over HTTP/3.0 request: ---> %s", req))

		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
		w.WriteHeader(http.StatusOK)

		return true, h.udpProxyServer.HandlePacket(*(w.(http3.HTTPStreamer).HTTPStream()), req, rconn)
	default:
		return false, nil
	}
}

var (
	_ Payload = (*BytePayload)(nil)
	_ Payload = (*CompressedPayload)(nil)
	_ Payload = (*UncompressedPayload)(nil)
	_ Payload = (*CompressionAssignPayload)(nil)
	_ Payload = (*CompressionClosePayload)(nil)
)
