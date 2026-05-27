package fetcher

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

// newTransport builds an *http.Transport tuned for high-fanout HTTP scanning:
// HTTP/2 enabled, generous connection reuse, separate dial / TLS / response
// timeouts, optional explicit proxy. insecureTLS controls cert verification
// (default true to match Python's verify=False at nodeCommon.py:43, 165 etc).
func newTransport(insecureTLS bool, proxyRaw string) (*http.Transport, error) {
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
	return tr, nil
}
