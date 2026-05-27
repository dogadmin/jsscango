package types

import "time"

type URLKind uint8

const (
	KindBaseURL URLKind = iota
	KindNoJS
	KindJS
	KindStatic
	KindAPIPath
)

func (k URLKind) String() string {
	switch k {
	case KindBaseURL:
		return "base_url"
	case KindNoJS:
		return "no_js"
	case KindJS:
		return "js"
	case KindStatic:
		return "static_url"
	case KindAPIPath:
		return "api_path"
	}
	return "unknown"
}

func (k URLKind) MarshalJSON() ([]byte, error) {
	return []byte(`"` + k.String() + `"`), nil
}

type Target struct {
	URL        string    `json:"url"`
	Scheme     string    `json:"scheme,omitempty"`
	Host       string    `json:"host,omitempty"`
	Port       string    `json:"port,omitempty"`
	BaseDomain string    `json:"base_domain,omitempty"`
	Cookies    string    `json:"-"`
	Folder     string    `json:"folder,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
}

type DiscoveredURL struct {
	Target  string  `json:"target"`
	URL     string  `json:"url"`
	Referer string  `json:"referer,omitempty"`
	Kind    URLKind `json:"kind"`
	Depth   uint8   `json:"depth,omitempty"`
	Source  string  `json:"source,omitempty"`
}

type APIPath struct {
	Target  string `json:"target"`
	Referer string `json:"referer,omitempty"`
	Path    string `json:"api_path"`
	Pattern string `json:"pattern,omitempty"`
}

type ProbeResult struct {
	Target      string `json:"target"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size"`
	BodyPath    string `json:"body_path,omitempty"`
	Referer     string `json:"referer,omitempty"`
	Parameter   string `json:"parameter,omitempty"`
	BodySHA256  string `json:"body_sha256,omitempty"`
	Kept        bool   `json:"kept"`
	Duplicate   bool   `json:"duplicate,omitempty"`
}

type RuleHit struct {
	Target  string   `json:"target"`
	Kind    string   `json:"kind"`
	RuleID  string   `json:"rule_id"`
	Group   string   `json:"group,omitempty"`
	Matches []string `json:"matches"`
	URL     string   `json:"url,omitempty"`
	File    string   `json:"file,omitempty"`
}

type Match struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Group   string `json:"group,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Offset  int    `json:"offset,omitempty"`
}

type Summary struct {
	DurationMS     int64          `json:"duration_ms"`
	URLsDiscovered int            `json:"urls_discovered"`
	JSFetched      int            `json:"js_fetched"`
	APIPaths       int            `json:"api_paths"`
	Probes         int            `json:"probes"`
	RuleHits       int            `json:"rule_hits"`
	StageCounts    map[string]int `json:"stage_counts,omitempty"`
}

type Report struct {
	Schema  string         `json:"schema"`
	Time    time.Time      `json:"time"`
	Target  string         `json:"target"`
	Event   string         `json:"event"`
	URL     *DiscoveredURL `json:"discovered_url,omitempty"`
	API     *APIPath       `json:"api_path,omitempty"`
	Probe   *ProbeResult   `json:"probe,omitempty"`
	Hit     *RuleHit       `json:"rule_hit,omitempty"`
	Stage   string         `json:"stage,omitempty"`
	Summary *Summary       `json:"summary,omitempty"`
}

const SchemaVersion = "getjsurlscan/v1"
