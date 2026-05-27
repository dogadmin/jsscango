package output

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xuri/excelize/v2"

	"github.com/dogadmin/jsscango/internal/types"
)

// Sheet names duplicate the original Python tool's (saveToExcel.py + the
// run_url callers in getJsUrl.py) so the existing chuli.py merge script can
// still consume our output.
const (
	sheetAllLoadedURLs    = "首页自动加载的所有URL列表"
	sheetHomepageJSURLs   = "首页自动加载的JS_URL列表"
	sheetHomepageNonJS    = "首页自动加载的属于目标的非JS_URL列表"
	sheetAllJS            = "所有存活的js"
	sheetAllStatic        = "所有存活的静态url"
	sheetAPIPaths         = "API接口列表"
	sheetFrontendRoutes   = "前端路由 (Vue Router)"
	sheetProbeResponses   = "探测响应"
	sheetFingerprintHits  = "hae检测结果"
	sheetSensitiveHits    = "敏感信息检测结果"
)

// XLSX buffers events in memory per target then writes a multi-sheet workbook
// at Close. Memory cost is bounded by --max-depth + per-host-qps; for very
// large crawls this could be hundreds of MiB, which is acceptable.
type XLSX struct {
	OutDir string

	mu     sync.Mutex
	target string
	folder string

	allLoaded      []types.DiscoveredURL
	js             []types.DiscoveredURL
	nonJS          []types.DiscoveredURL
	allJS          []types.DiscoveredURL
	allStatic      []types.DiscoveredURL
	apiPaths       []types.APIPath
	frontendRoutes []types.DiscoveredURL
	probes         []types.ProbeResult
	fingerprintHs  []types.RuleHit
	sensitiveHs    []types.RuleHit
}

func NewXLSX(outDir string) *XLSX { return &XLSX{OutDir: outDir} }

func (x *XLSX) Start(_ context.Context, targetFolder string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	// Reset per-target buffers field by field; we can't `*x = XLSX{...}`
	// because that would clobber the held mutex.
	x.folder = targetFolder
	x.target = ""
	x.allLoaded = nil
	x.js = nil
	x.nonJS = nil
	x.allJS = nil
	x.allStatic = nil
	x.apiPaths = nil
	x.frontendRoutes = nil
	x.probes = nil
	x.fingerprintHs = nil
	x.sensitiveHs = nil
	return os.MkdirAll(filepath.Join(x.OutDir, targetFolder), 0o755)
}

func (x *XLSX) Write(r types.Report) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.target == "" {
		x.target = r.Target
	}
	switch r.Event {
	case "discovered_url":
		if r.URL == nil {
			return nil
		}
		x.allLoaded = append(x.allLoaded, *r.URL)
		switch r.URL.Source {
		case "homepage", "chromedp":
			switch r.URL.Kind {
			case types.KindJS:
				x.js = append(x.js, *r.URL)
			case types.KindNoJS, types.KindBaseURL:
				x.nonJS = append(x.nonJS, *r.URL)
			}
		}
		switch r.URL.Kind {
		case types.KindJS:
			x.allJS = append(x.allJS, *r.URL)
		case types.KindStatic:
			x.allStatic = append(x.allStatic, *r.URL)
		}
	case "api_path":
		if r.API != nil {
			x.apiPaths = append(x.apiPaths, *r.API)
		}
	case "frontend_route":
		// Pipeline emits one frontend_route event per Vue Router /
		// SPA-router path. Captured into its own sheet so the operator
		// can spot the routes the chromedp recursion should navigate to
		// without having to grep through the discovered_url stream.
		if r.URL != nil {
			x.frontendRoutes = append(x.frontendRoutes, *r.URL)
		}
	case "probe":
		if r.Probe != nil && r.Probe.Kept {
			x.probes = append(x.probes, *r.Probe)
		}
	case "rule_hit":
		if r.Hit == nil {
			return nil
		}
		switch r.Hit.Kind {
		case "sensitive":
			x.sensitiveHs = append(x.sensitiveHs, *r.Hit)
		default: // fingerprint, vuln, anything else
			x.fingerprintHs = append(x.fingerprintHs, *r.Hit)
		}
	}
	return nil
}

func (x *XLSX) Flush() error { return nil }

func (x *XLSX) Close() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.folder == "" {
		return nil
	}

	f := excelize.NewFile()
	defer f.Close()
	// excelize creates a default "Sheet1" — we'll replace it with our first
	// real sheet to keep the workbook clean.
	defaultSheet := f.GetSheetName(0)

	writeDiscoveredSheet(f, sheetAllLoadedURLs, x.allLoaded)
	writeDiscoveredSheet(f, sheetHomepageJSURLs, x.js)
	writeDiscoveredSheet(f, sheetHomepageNonJS, x.nonJS)
	writeDiscoveredSheet(f, sheetAllJS, x.allJS)
	writeDiscoveredSheet(f, sheetAllStatic, x.allStatic)
	writeAPISheet(f, sheetAPIPaths, x.apiPaths)
	writeRouteSheet(f, sheetFrontendRoutes, x.frontendRoutes)
	writeProbeSheet(f, sheetProbeResponses, x.probes)
	writeRuleSheet(f, sheetFingerprintHits, x.fingerprintHs)
	writeRuleSheet(f, sheetSensitiveHits, x.sensitiveHs)

	// Drop the default empty sheet (only if more sheets exist).
	if len(f.GetSheetList()) > 1 {
		_ = f.DeleteSheet(defaultSheet)
	}

	name := filepath.Join(x.OutDir, x.folder, "report.xlsx")
	if err := f.SaveAs(name); err != nil {
		return fmt.Errorf("save xlsx: %w", err)
	}
	return nil
}

func writeDiscoveredSheet(f *excelize.File, name string, rows []types.DiscoveredURL) {
	idx, err := f.NewSheet(name)
	if err != nil {
		return
	}
	if idx == 0 {
		// already exists / failed; nothing to do
	}
	header := []interface{}{"URL", "Kind", "Referer", "Source", "Depth"}
	_ = f.SetSheetRow(name, "A1", &header)
	for i, r := range rows {
		row := []interface{}{
			sanitizeXLSXCell(r.URL),
			r.Kind.String(),
			sanitizeXLSXCell(r.Referer),
			r.Source,
			int(r.Depth),
		}
		_ = f.SetSheetRow(name, fmt.Sprintf("A%d", i+2), &row)
	}
}

func writeAPISheet(f *excelize.File, name string, rows []types.APIPath) {
	if _, err := f.NewSheet(name); err != nil {
		return
	}
	header := []interface{}{"API Path", "Referer", "Pattern"}
	_ = f.SetSheetRow(name, "A1", &header)
	for i, r := range rows {
		row := []interface{}{
			sanitizeXLSXCell(r.Path),
			sanitizeXLSXCell(r.Referer),
			r.Pattern,
		}
		_ = f.SetSheetRow(name, fmt.Sprintf("A%d", i+2), &row)
	}
}

// writeRouteSheet writes the Vue Router / SPA-router routes sheet. Columns
// mirror the discovered_url sheet's first four (Target / Path / Source /
// Referer) — the operator needs to see where each route came from so they
// can correlate it back to the source JS file.
func writeRouteSheet(f *excelize.File, name string, rows []types.DiscoveredURL) {
	if _, err := f.NewSheet(name); err != nil {
		return
	}
	header := []interface{}{"Target", "Path", "Source", "Referer"}
	_ = f.SetSheetRow(name, "A1", &header)
	for i, r := range rows {
		row := []interface{}{
			sanitizeXLSXCell(r.Target),
			sanitizeXLSXCell(r.URL),
			r.Source,
			sanitizeXLSXCell(r.Referer),
		}
		_ = f.SetSheetRow(name, fmt.Sprintf("A%d", i+2), &row)
	}
}

func writeProbeSheet(f *excelize.File, name string, rows []types.ProbeResult) {
	if _, err := f.NewSheet(name); err != nil {
		return
	}
	// Source is appended at the end so existing consumers (chuli.py et al.)
	// keep their column indices stable; new tooling can read column I.
	header := []interface{}{"URL", "Method", "Status", "Content-Type", "Size", "Body Path", "SHA256", "Duplicate", "Source"}
	_ = f.SetSheetRow(name, "A1", &header)
	for i, r := range rows {
		row := []interface{}{
			sanitizeXLSXCell(r.URL),
			r.Method,
			r.StatusCode,
			r.ContentType,
			r.Size,
			r.BodyPath,
			r.BodySHA256,
			r.Duplicate,
			r.Source,
		}
		_ = f.SetSheetRow(name, fmt.Sprintf("A%d", i+2), &row)
	}
}

func writeRuleSheet(f *excelize.File, name string, rows []types.RuleHit) {
	if _, err := f.NewSheet(name); err != nil {
		return
	}
	header := []interface{}{"Rule ID", "Kind", "Group", "Matches", "File", "URL"}
	_ = f.SetSheetRow(name, "A1", &header)
	for i, r := range rows {
		row := []interface{}{
			r.RuleID,
			r.Kind,
			r.Group,
			sanitizeXLSXCell(strings.Join(r.Matches, " | ")),
			r.File,
			sanitizeXLSXCell(r.URL),
		}
		_ = f.SetSheetRow(name, fmt.Sprintf("A%d", i+2), &row)
	}
}

// excelize / Excel reject control characters U+0000-U+001F (except tab/CR/LF)
// and U+007F. Strip them to avoid file-open errors. Mirrors the
// ILLEGAL_CHARACTERS_RE used at saveToExcel.py:16.
func sanitizeXLSXCell(s string) string {
	if s == "" {
		return s
	}
	b := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			b = append(b, r)
		case r >= 0 && r < 0x20:
			// drop
		case r == 0x7f:
			// drop
		default:
			b = append(b, r)
		}
	}
	// Excel cell limit is 32767 chars.
	if len(b) > 32760 {
		b = b[:32760]
	}
	return string(b)
}
