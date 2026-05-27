package fetcher

import (
	"context"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// helloIDFor maps the public fingerprint string to a utls ClientHelloID.
// The bool return is false for the "go" sentinel, signalling the caller
// to fall back to the stdlib TLS path.
func helloIDFor(fingerprint string) (utls.ClientHelloID, bool) {
	switch fingerprint {
	case "chrome120":
		return utls.HelloChrome_120, true
	case "firefox120":
		return utls.HelloFirefox_120, true
	case "safari17":
		// utls's newest published Safari parrot is 16.0; closest mimicry
		// of recent Safari builds (including 17.x).
		return utls.HelloSafari_16_0, true
	case "go", "":
		return utls.ClientHelloID{}, false
	default:
		// Unknown values fall back to stdlib so callers don't silently get
		// a wrong fingerprint. Config-layer Normalize() should have caught
		// this already.
		return utls.ClientHelloID{}, false
	}
}

// forceHTTP1ALPN walks the ClientHelloSpec's extension list and rewrites any
// ALPN extension so it advertises only "http/1.1". This keeps the JA3
// fingerprint identical to the chosen browser parrot (JA3 hashes extension
// IDs, not their ALPN string contents) while ensuring the server picks h1
// — which is required because net/http's *http.Transport only routes
// negotiated h2 connections through its http2 path when the underlying conn
// is a stdlib *tls.Conn (see net/http/transport.go dialConn). A utls.UConn
// fails that type assertion, so h2-negotiated conns are mis-handled as h1
// and the response stream is unreadable. Forcing http/1.1 at the ALPN layer
// sidesteps the issue cleanly.
func forceHTTP1ALPN(spec *utls.ClientHelloSpec) {
	for _, ext := range spec.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			a.AlpnProtocols = []string{"http/1.1"}
		}
	}
}

// MakeUTLSDialer returns a DialTLSContext-compatible function that performs
// a utls handshake mimicking the given fingerprint. Returns nil when
// fingerprint == "go", meaning the caller should use the stdlib path.
//
// The SNI is extracted from the dial address (host portion of host:port).
// The ALPN list is constrained to ["http/1.1"] at the wire level so the
// resulting *utls.UConn is consumable by net/http's HTTP/1.1 transport
// machinery without the *tls.Conn type-assertion pitfalls in the standard
// library. JA3 stays Chrome-perfect (extension IDs / ordering unchanged);
// JA4 is slightly degraded because ALPN values are part of that hash.
func MakeUTLSDialer(fingerprint string, insecureSkipVerify bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	helloID, ok := helloIDFor(fingerprint)
	if !ok {
		return nil
	}
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			// addr without an explicit port: use whole addr as SNI.
			host = addr
		}
		cfg := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec — opt-in via --secure-tls
			// NextProtos is overridden by ApplyPreset below, but is also the
			// fallback for environments that bypass the preset path. Keep it
			// consistent with the wire-level ALPN forced in forceHTTP1ALPN: the
			// h2 path is unreachable because of the *tls.Conn type-assertion
			// bug in net/http's transport when DialTLSContext returns a non-stdlib
			// conn (utls.UConn). See utls_dialer.go top comment.
			NextProtos: []string{"http/1.1"},
		}
		// Build the parrot from the spec so we can rewrite its ALPN. Using
		// HelloCustom + ApplyPreset is the documented path for tweaking a
		// canned ClientHello while keeping its cipher/extension/curve
		// signature intact.
		spec, err := utls.UTLSIdToSpec(helloID)
		if err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("utls spec lookup: %w", err)
		}
		forceHTTP1ALPN(&spec)
		uconn := utls.UClient(raw, cfg, utls.HelloCustom)
		if err := uconn.ApplyPreset(&spec); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("utls apply preset: %w", err)
		}
		if err := uconn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("utls handshake: %w", err)
		}
		return uconn, nil
	}
}
