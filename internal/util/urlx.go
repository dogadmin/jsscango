package util

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// BaseDomain returns the eTLD+1 label of the URL host (the registered domain
// "label" part, not including the public suffix). Mirrors tldextract.extract().domain
// from getJsUrl.py:18. For IPs returns the IP literal.
func BaseDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	if dot := strings.IndexByte(etld1, '.'); dot > 0 {
		return etld1[:dot]
	}
	return etld1
}

// HostKey returns "host:port" for rate-limiter and connection-pool keys.
// For default ports it normalizes to just "host".
func HostKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// IsIP reports whether s is a literal IPv4/IPv6 address. Mirrors is_ip in
// nodeCommon.py:232.
func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

// IsBlacklistedDomain checks whether the URL host (eTLD+1) is in blackDomain,
// or its bare netloc contains any blackURL substring. Mirrors is_blacklisted
// in nodeCommon.py:186.
func IsBlacklistedDomain(rawURL string, blackDomain, blackURL []string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	var registered string
	if ip := net.ParseIP(host); ip != nil {
		registered = host
	} else if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		registered = d
	} else {
		registered = host
	}
	for _, b := range blackDomain {
		if registered == b {
			return true
		}
	}
	netloc := u.Host
	for _, b := range blackURL {
		if strings.Contains(netloc, b) {
			return true
		}
	}
	return false
}

// SameSiteOrIP returns true when target's host shares the given base domain,
// or when target's host is a literal IP (always allowed). Mirrors
// filter_base_urls in getJsUrl.py:22.
//
// TODO(phase4): substring match over the host string matches
// "evil-example-attacker.com" against baseDomain="example". This is faithful
// to the Python source's `base_domain in url` but worth tightening to
// eTLD+1 equality once cross-origin coverage tests exist.
func SameSiteOrIP(targetURL, baseDomain string) bool {
	u, err := url.Parse(targetURL)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return true
	}
	return baseDomain != "" && strings.Contains(host, baseDomain)
}

// JoinNewURL reconstructs an absolute URL from a path fragment found inside a
// page at base (scheme://host[:port]) with directory rootPath (e.g. "/static/js/").
// Mirrors get_new_url in jsAndStaticUrlFind.py:99.
func JoinNewURL(scheme, base, rootPath, path string) string {
	if path == "" || path == "/" || path == "//" {
		return ""
	}
	switch {
	case strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://"):
		return path
	case strings.HasPrefix(path, "//"):
		return scheme + ":" + path
	case strings.HasPrefix(path, "/"):
		return base + path
	case strings.HasPrefix(path, "js/"):
		return base + "/" + path
	}
	if strings.Contains(path, "/") {
		return base + "/" + path
	}
	if !strings.HasSuffix(rootPath, "/") {
		rootPath += "/"
	}
	return base + rootPath + path
}

// SplitBase returns (scheme, base, rootPath) for a URL where base is
// "scheme://host[:port]" and rootPath is the parent directory of the URL path
// ending with "/". rootPath defaults to "/" when the path has no directory.
func SplitBase(rawURL string) (scheme, base, rootPath string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", "/"
	}
	scheme = u.Scheme
	base = scheme + "://" + u.Host
	p := u.Path
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		rootPath = p[:i+1]
	} else {
		rootPath = "/"
	}
	if rootPath == "" {
		rootPath = "/"
	}
	return
}
