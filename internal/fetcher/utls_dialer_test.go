package fetcher

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestMakeUTLSDialer_FingerprintMapping(t *testing.T) {
	cases := []struct {
		in      string
		wantNil bool
	}{
		{"chrome120", false},
		{"firefox120", false},
		{"safari17", false},
		{"go", true},
		{"", true},
		{"unknown-value", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := MakeUTLSDialer(c.in, false)
			if c.wantNil && got != nil {
				t.Errorf("MakeUTLSDialer(%q) = non-nil, want nil", c.in)
			}
			if !c.wantNil && got == nil {
				t.Errorf("MakeUTLSDialer(%q) = nil, want non-nil", c.in)
			}
		})
	}
}

func TestForceHTTP1ALPN_RewritesExtension(t *testing.T) {
	// Synthesize a minimal ClientHelloSpec with an ALPN advertising h2.
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		},
	}
	forceHTTP1ALPN(spec)
	a, ok := spec.Extensions[0].(*utls.ALPNExtension)
	if !ok {
		t.Fatalf("expected ALPNExtension, got %T", spec.Extensions[0])
	}
	if len(a.AlpnProtocols) != 1 || a.AlpnProtocols[0] != "http/1.1" {
		t.Errorf("AlpnProtocols = %v, want [http/1.1]", a.AlpnProtocols)
	}
}

func TestForceHTTP1ALPN_NoALPNExtension(t *testing.T) {
	// forceHTTP1ALPN should be a no-op when the spec has no ALPN ext.
	spec := &utls.ClientHelloSpec{}
	// Just verify it doesn't panic.
	forceHTTP1ALPN(spec)
}
