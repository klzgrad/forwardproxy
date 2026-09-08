package forwardproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func connectTestRequest(version int) *http.Request {
	r := &http.Request{
		Method:     http.MethodConnect,
		Host:       "192.0.2.1:443",
		URL:        &url.URL{Host: "192.0.2.1:443"},
		Header:     make(http.Header),
		Body:       http.NoBody,
		ProtoMajor: version,
	}
	return r.WithContext(context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
}

func requireConnectStatus(t *testing.T, err error, status int) {
	t.Helper()
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != status {
		t.Fatalf("handler error = %v, want status %d", err, status)
	}
}

func TestCONNECTDialFailureResponse(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		for _, upstream := range []bool{false, true} {
			for _, tc := range []struct {
				name   string
				err    error
				status int
			}{
				{"refused", errors.New("connection refused"), http.StatusBadGateway},
				{"deadline", context.DeadlineExceeded, http.StatusGatewayTimeout},
				{"net-timeout", &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}, http.StatusGatewayTimeout},
			} {
				t.Run(fmt.Sprintf("h%d/upstream=%t/%s", version, upstream, tc.name), func(t *testing.T) {
					w := httptest.NewRecorder()
					dialed := false
					h := &Handler{
						HideIP:   true,
						aclRules: []aclRule{&aclAllRule{allow: true}},
						dialContext: func(context.Context, string, string) (net.Conn, error) {
							dialed = true
							if w.Flushed {
								t.Error("CONNECT committed success before dialing")
							}
							return nil, tc.err
						},
					}
					if upstream {
						h.upstream = &url.URL{Scheme: "https", Host: "proxy.example:443"}
					}
					err := h.ServeHTTP(w, connectTestRequest(version), nil)
					requireConnectStatus(t, err, tc.status)
					if !dialed || w.Flushed {
						t.Fatalf("dialed=%t response committed=%t", dialed, w.Flushed)
					}
					if w.Header().Get("Padding") == "" {
						t.Fatal("failure response lost padding negotiation")
					}
					// Caddy must still be able to write the error status.
					w.WriteHeader(tc.status)
					if w.Code != tc.status {
						t.Fatalf("response status = %d, want %d", w.Code, tc.status)
					}
				})
			}
		}
	}
}

func TestCONNECTACLFailureResponse(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", version), func(t *testing.T) {
			w := httptest.NewRecorder()
			h := &Handler{
				HideIP:   true,
				aclRules: []aclRule{&aclAllRule{allow: false}},
				dialContext: func(context.Context, string, string) (net.Conn, error) {
					t.Error("ACL-denied address was dialed")
					return nil, errors.New("unexpected dial")
				},
			}
			requireConnectStatus(t, h.ServeHTTP(w, connectTestRequest(version), nil), http.StatusForbidden)
			if w.Flushed {
				t.Fatal("ACL failure already committed success")
			}
		})
	}
}

func TestCONNECTSuccessFlushesBeforeTargetData(t *testing.T) {
	for _, version := range []int{2, 3} {
		t.Run(fmt.Sprintf("h%d", version), func(t *testing.T) {
			w := httptest.NewRecorder()
			target, peer := net.Pipe()
			defer target.Close()
			defer peer.Close()
			// Reads return EOF without a target response body.
			peer.Close()
			h := &Handler{
				HideIP:   true,
				aclRules: []aclRule{&aclAllRule{allow: true}},
				dialContext: func(context.Context, string, string) (net.Conn, error) {
					if w.Flushed {
						t.Error("CONNECT committed success before dialing")
					}
					return target, nil
				},
			}
			if err := h.ServeHTTP(w, connectTestRequest(version), nil); err != nil {
				t.Fatal(err)
			}
			if !w.Flushed || w.Code != http.StatusOK {
				t.Fatalf("success response: flushed=%t status=%d", w.Flushed, w.Code)
			}
		})
	}
}
