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

// XLSX buffers events in memory and writes a multi-sheet workbook at Close.
// When Split is false (default) one combined workbook collects rows from
// every target the pipeline processes and is written to <OutDir>/report.xlsx
// at the very end; the Target column on every sheet distinguishes them.
// When Split is true, each Start() flushes the prior target's rows to its
// own per-target report.xlsx and resets the buffers, preserving the legacy
// one-xlsx-per-target layout.
type XLSX struct {
	OutDir string
	Split  bool // when true, write per-target xlsx instead of one combined file
	// Concurrent, when true, signals that multiple targets will call
	// Start simultaneously. In that mode Split MUST be false (the CLI
	// enforces this) — combined-mode Start just ensures the per-target
	// subdir exists and never mutates x.folder, so concurrent Starts
	// are safe.
	Concurrent bool

	mu     sync.Mutex
	folder string // current target's folder (per-target subdir; combined mode: last started)

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
	// In split mode, flushing happens on each new Start (writes the prior
	// target's workbook, then resets). In combined mode we keep accumulating
	// across all targets and write only once at Close.
	if x.Split && x.folder != "" && x.folder != targetFolder {
		if err := x.writeWorkbook(filepath.Join(x.OutDir, x.folder, "report.xlsx")); err != nil {
			return err
		}
		x.resetBuffers()
	}
	// In concurrent combined mode we don't track a single "current"
	// folder — every row carries a Target column and the combined
	// workbook is written at OutDir/report.xlsx in Close. Skipping the
	// x.folder write removes the only race that could blow up under
	// parallel Starts. Split-mode concurrent is forbidden by the CLI;
	// the defensive check below is belt-and-suspenders.
	if !x.Concurrent {
		x.folder = targetFolder
	} else if x.Split {
		return fmt.Errorf("xlsx: split mode is incompatible with concurrent targets")
	}
	return os.MkdirAll(filepath.Join(x.OutDir, targetFolder), 0o755)
}

func (x *XLSX) resetBuffers() {
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
}

func (x *XLSX) Write(r types.Report) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	switch r.Event {
	case "discovered_url":
		if r.URL == nil {
			return nil
		}
		u := *r.URL
		if u.Target == "" {
			u.Target = r.Target
		}
		x.allLoaded = append(x.allLoaded, u)
		switch u.Source {
		case "homepage", "chromedp":
			switch u.Kind {
			case types.KindJS:
				x.js = append(x.js, u)
			case types.KindNoJS, types.KindBaseURL:
				x.nonJS = append(x.nonJS, u)
			}
		}
		switch u.Kind {
		case types.KindJS:
			x.allJS = append(x.allJS, u)
		case types.KindStatic:
			x.allStatic = append(x.allStatic, u)
		}
	case "api_path":
		if r.API != nil {
			a := *r.API
			if a.Target == "" {
				a.Target = r.Target
			}
			x.apiPaths = append(x.apiPaths, a)
		}
	case "frontend_route":
		if r.URL != nil {
			u := *r.URL
			if u.Target == "" {
				u.Target = r.Target
			}
			x.frontendRoutes = append(x.frontendRoutes, u)
		}
	case "probe":
		if r.Probe != nil && r.Probe.Kept {
			pr := *r.Probe
			if pr.Target == "" {
				pr.Target = r.Target
			}
			x.probes = append(x.probes, pr)
		}
	case "rule_hit":
		if r.Hit == nil {
			return nil
		}
		h := *r.Hit
		if h.Target == "" {
			h.Target = r.Target
		}
		switch h.Kind {
		case "sensitive":
			x.sensitiveHs = append(x.sensitiveHs, h)
		default: // fingerprint, vuln, anything else
			x.fingerprintHs = append(x.fingerprintHs, h)
		}
	}
	return nil
}

func (x *XLSX) Flush() error { return nil }

func (x *XLSX) Close() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	// Nothing buffered AND no folder seen — Pipeline never ran a target,
	// so there's no workbook to write. Bail without creating an empty
	// report.xlsx.
	if x.folder == "" && !x.Concurrent &&
		len(x.allLoaded)+len(x.js)+len(x.nonJS)+len(x.allJS)+len(x.allStatic)+
			len(x.apiPaths)+len(x.frontendRoutes)+len(x.probes)+
			len(x.fingerprintHs)+len(x.sensitiveHs) == 0 {
		return nil
	}
	var name string
	if x.Split {
		// Split mode is single-target-at-a-time by design (each Start
		// rolls over the prior workbook); x.folder is therefore the
		// last target's folder.
		name = filepath.Join(x.OutDir, x.folder, "report.xlsx")
	} else {
		name = filepath.Join(x.OutDir, "report.xlsx")
		if err := os.MkdirAll(x.OutDir, 0o755); err != nil {
			return err
		}
	}
	return x.writeWorkbook(name)
}

// writeWorkbook serializes the currently-buffered rows to the given path.
// Caller must hold x.mu.
func (x *XLSX) writeWorkbook(name string) error {
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

	if err := f.SaveAs(name); err != nil {
		return fmt.Errorf("save xlsx: %w", err)
	}
	return nil
}

func writeDiscoveredSheet(f *excelize.File, name string, rows []types.DiscoveredURL) {
	if _, err := f.NewSheet(name); err != nil {
		return
	}
	header := []interface{}{"Target", "URL", "Kind", "Referer", "Source", "Depth"}
	_ = f.SetSheetRow(name, "A1", &header)
	for i, r := range rows {
		row := []interface{}{
			sanitizeXLSXCell(r.Target),
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
	header := []interface{}{"Target", "API Path", "Method", "Referer", "Pattern"}
	_ = f.SetSheetRow(name, "A1", &header)
	for i, r := range rows {
		row := []interface{}{
			sanitizeXLSXCell(r.Target),
			sanitizeXLSXCell(r.Path),
			r.Method,
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
	header := []interface{}{"Target", "URL", "Method", "Status", "Content-Type", "Size", "Body Path", "SHA256", "Duplicate", "Source"}
	_ = f.SetSheetRow(name, "A1", &header)
	for i, r := range rows {
		row := []interface{}{
			sanitizeXLSXCell(r.Target),
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
	header := []interface{}{"Target", "Rule ID", "Kind", "Group", "Matches", "File", "URL"}
	_ = f.SetSheetRow(name, "A1", &header)
	for i, r := range rows {
		row := []interface{}{
			sanitizeXLSXCell(r.Target),
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
