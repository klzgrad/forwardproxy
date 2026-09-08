package forwardproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/forwardproxy/httpclient"
)

func TestCONNECTRequestCancellation(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		for _, upstream := range []bool{false, true} {
			t.Run(fmt.Sprintf("h%d/upstream=%t", version, upstream), func(t *testing.T) {
				r := connectTestRequest(version)
				r.Header.Set("Forwarded", "for=192.0.2.10")
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				w := httptest.NewRecorder()
				h := &Handler{
					aclRules: []aclRule{&aclAllRule{allow: true}},
					dialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
						headers, ok := dialCtx.Value(httpclient.ContextKeyHeader{}).(http.Header)
						if !ok || headers.Get("Forwarded") != "for=192.0.2.10" {
							t.Error("forwarding headers were not preserved in the dial context")
						}
						cancel()
						select {
						case <-dialCtx.Done():
							return nil, dialCtx.Err()
						case <-time.After(time.Second):
							t.Error("request cancellation did not reach the dial")
							return nil, errors.New("dial was not canceled")
						}
					},
				}
				if upstream {
					h.upstream = &url.URL{Scheme: "https", Host: "proxy.example:443"}
				}
				requireConnectStatus(t, h.ServeHTTP(w, r.WithContext(ctx), nil), http.StatusBadGateway)
				if w.Flushed {
					t.Fatal("canceled CONNECT committed success")
				}
			})
		}
	}
}

func TestCONNECTCanceledLateDialSuccess(t *testing.T) {
	for _, upstream := range []bool{false, true} {
		t.Run(fmt.Sprintf("upstream=%t", upstream), func(t *testing.T) {
			r := connectTestRequest(2)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			target, peer := net.Pipe()
			defer target.Close()
			defer peer.Close()
			h := &Handler{
				HideIP:   true,
				aclRules: []aclRule{&aclAllRule{allow: true}},
				dialContext: func(context.Context, string, string) (net.Conn, error) {
					cancel()
					return target, nil
				},
			}
			if upstream {
				h.upstream = &url.URL{Scheme: "https", Host: "proxy.example:443"}
			}
			conn, err := h.dialContextCheckACL(ctx, "tcp", r.Host)
			if conn != nil {
				conn.Close()
				t.Fatal("canceled dial returned a successful connection")
			}
			requireConnectStatus(t, err, http.StatusBadGateway)
			peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := peer.Read(make([]byte, 1)); err == nil {
				t.Fatal("late connection was not closed")
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Fatal("late connection leaked until the read deadline")
			}
		})
	}
}

func TestCONNECTDNSCancellation(t *testing.T) {
	// Keep DNS local and blocked until cancellation, without changing OS DNS.
	started := make(chan struct{})
	stop := make(chan struct{})
	var once sync.Once
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			once.Do(func() { close(started) })
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-stop:
				return nil, errors.New("test resolver stopped")
			}
		},
	}
	defer func() { net.DefaultResolver = previous }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	finished := make(chan struct{})
	h := &Handler{
		aclRules: []aclRule{&aclAllRule{allow: true}},
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("DNS returned an unexpected candidate")
		},
	}
	go func() {
		defer close(finished)
		_, err := h.dialContextCheckACL(ctx, "tcp", "cancel.example.invalid:443")
		done <- err
	}()
	defer func() {
		cancel()
		close(stop)
		<-finished
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("DNS did not start")
	}
	cancel()
	select {
	case err := <-done:
		requireConnectStatus(t, err, http.StatusBadGateway)
	case <-time.After(time.Second):
		t.Fatal("DNS did not stop after request cancellation")
	}
}

func TestCONNECTExpiredDNSDeadline(t *testing.T) {
	h := &Handler{aclRules: []aclRule{&aclAllRule{allow: true}}}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := h.dialContextCheckACL(ctx, "tcp", "deadline.example.invalid:443")
	requireConnectStatus(t, err, http.StatusGatewayTimeout)
}

func TestCONNECTUpstreamContextSurvivesDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target, peer := net.Pipe()
	defer target.Close()
	defer peer.Close()
	var tunnelCtx context.Context
	h := &Handler{
		upstream: &url.URL{Scheme: "https", Host: "proxy.example:443"},
		dialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			tunnelCtx = ctx
			return target, nil
		},
	}
	conn, err := h.dialContextCheckACL(ctx, "tcp", "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tunnelCtx.Err() != nil {
		t.Fatal("upstream context was canceled when dialing returned")
	}
	cancel()
	if !errors.Is(tunnelCtx.Err(), context.Canceled) {
		t.Fatal("upstream tunnel lost request cancellation")
	}
}
