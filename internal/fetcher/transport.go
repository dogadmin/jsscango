package fetcher

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"
)

// newTransport builds an *http.Transport tuned for high-fanout HTTP scanning:
// HTTP/2 enabled, generous connection reuse, separate dial / TLS / response
// timeouts, optional explicit proxy. insecureTLS controls cert verification
// (default true to match Python's verify=False at nodeCommon.py:43, 165 etc).
// fingerprint selects the TLS ClientHello mimicry; "go" (or empty) keeps
// the stdlib handshake, anything else wires utls via DialTLSContext.
func newTransport(insecureTLS bool, proxyRaw, fingerprint string) (*http.Transport, error) {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureTLS}, //nolint:gosec — opt-in via --secure-tls
	}
	if proxyRaw != "" {
		u, err := url.Parse(proxyRaw)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(u)
	}
	if dial := MakeUTLSDialer(fingerprint, insecureTLS); dial != nil {
		// utls owns the TLS handshake (including ALPN). Disable the stdlib
		// HTTP/2 auto-upgrade path because net/http only routes h2 conns
		// through TLSNextProto when the underlying type is *tls.Conn — a
		// utls.UConn isn't, so we constrain the wire-level ALPN inside the
		// dialer to "http/1.1" and let HTTP/1.1 carry the request.
		// http2.ConfigureTransport is still called below so the protocol
		// is registered as supported for any non-utls fallback paths and
		// to surface the http2 dependency explicitly (per task spec).
		tr.DialTLSContext = dial
		tr.ForceAttemptHTTP2 = false
		if err := http2.ConfigureTransport(tr); err != nil {
			return nil, err
		}
	}
	return tr, nil
}
