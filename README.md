# jsscango

JavaScript / static URL / API endpoint scanner. A Go rewrite of the Python
`getjsurlscan` tool, optimised for throughput, accuracy, and a clean
machine-readable output format.

## What it does

Given a list of target URLs, jsscango walks the site's JavaScript bundles to
discover hidden API paths, then optionally probes those endpoints and scans
the responses for sensitive data leaks (JWT, cloud access keys, webhooks,
internal IPs, etc.).

Framework-aware extraction since v0.4.0: axios `baseURL` is parsed out of
each JS file and prepended to relative paths in that file; `url+method`
pairs in axios configs feed declared verbs to the prober; Vue Router
routes are detected and routed to their own sheet (not probed as APIs).

Stages per target:

| # | Stage | What |
|---|---|---|
| 0 | well-known | robots.txt, sitemap.xml, OpenAPI/Swagger docs, Spring Actuator. |
| 1 | homepage | Parse `<script src>` from the target page (static) or capture network events from a headless browser (chromedp). |
| 2 | crawl | BFS the JS files found in stage 1, extracting more JS, static, API paths, and SPA routes. Bounded by `--max-depth`. |
| 3 | api-path | Filter candidates through union regex + structural false-positive predicates. Vue Router routes are reclassified out. |
| 4 | probe | Send the declared verb (when extraction recovered one) or the action-aware fan-out (GET always; POST_JSON when the path matches a state-changing verb pattern). Dangerous endpoints (`delete`, `logout`, …) are skipped. |
| 4b | ancestor recurse | For each 2xx kept hit, ascend up to N parent paths (`--ancestor-recurse-depth=2`) and probe them as index endpoints. |
| 5 | postprocess | Apply the rule set to every saved response body, emitting fingerprint / vuln / sensitive hits. |

## Differences vs the Python original

- **Concurrency**: per-stage worker pools (`errgroup` + `semaphore`) instead of
  300 raw threads per stage with `time.sleep(0.2)` stagger. Per-host token
  bucket rate limit (`golang.org/x/time/rate`) prevents hammering a single
  backend.
- **HTTP**: single `*http.Client` with HTTP/2 + connection reuse + retry with
  jitter; body size bounded by `--max-body-mb`. JA3 fingerprint mimicry
  via utls (`chrome120|firefox120|safari17|go`).
- **Framework-aware extraction**: axios `baseURL` / `url+method` /
  Vue Router routes are parsed statically; relative paths get prefixed
  correctly, declared verbs override the fan-out.
- **Dedup**: response-body SHA256 dedup at probe time, not as a post-hoc step.
- **Safety**: replaces the Python tool's `eval(response_body)` parameter
  miner (RCE risk) with `json.Unmarshal` plus regex.
- **Rules**: 72 regex rules (HaE community set @ 8f363507 merged with
  jsscango originals) + 68 blacktext markers. Embedded via `go:embed`,
  auto-materialised to `<user-config-dir>/jsscango/rules.yaml` on first
  run so edits stick across upgrades. Override with `--rules path/to/rules.yaml`.
- **Output**: streaming JSONL plus a single combined XLSX with `Target`
  column on every sheet (`--xlsx-split` for one-xlsx-per-target legacy
  layout). Both written from the same event stream.
- **Logging**: stderr gets WARN+ only; full INFO/DEBUG streams to
  `<out>/scan.log`. `--verbose` lifts stderr to `--log-level`.
- **Probe URL permutation**: Python-parity Cartesian expansion of
  derived bases × api-prefix-split paths (multi-host coverage when
  chromedp captured XHRs from sibling hosts). `--permutate-probe=false`
  to disable.
- **Crawl depth**: BFS bounded by `--max-depth` (default 3) so cyclic
  webpack imports terminate.

## Install

Prebuilt binaries for linux/darwin/windows × amd64/arm64 are attached to
each GitHub release: <https://github.com/dogadmin/jsscango/releases>.

Or build from source (Go 1.22+):

```sh
go build -o jsscango ./cmd/getjsurlscan
```

## Usage

```sh
# scan a single target
jsscango scan -u https://example.com/

# scan from a file (one URL per line; "#" comments allowed)
jsscango scan -f targets.txt --workers 32 --per-host-qps 5

# collect URLs only, no probing
jsscango scan -u https://example.com/ --no-probe

# use external rules
jsscango scan -u https://example.com/ --rules my-rules.yaml

# show where the user-config rules.yaml lives + which layer wins
jsscango rules path

# more aggressive: lift the per-host throttle, larger probe pool
jsscango scan -f targets.txt --per-host-qps 20 --workers-probe 128
```

Run `jsscango scan --help` for the full flag list.

### Output layout

```
results/
├── report.xlsx                       # combined, Target column on every sheet
├── scan.log                          # full INFO/DEBUG trail
├── <target1>/
│   ├── report.jsonl                  # per-target event stream
│   ├── state.json                    # resume cursor
│   └── response/                     # saved 2xx bodies
└── <target2>/
    └── ...
```

## Output

- **`report.jsonl`** (one per target, in `<target>/`) — one JSON object per line.
  Events: `stage`, `discovered_url`, `api_path`, `frontend_route`, `probe`,
  `rule_hit`, `summary`.
- **`report.xlsx`** (one combined file at `<out>/report.xlsx`) — 10 sheets,
  including the new `前端路由 (Vue Router)` and a `Source` column on
  `探测响应` distinguishing primary / permutate / ancestor_recurse hits.
  Sheet names match the original Python tool so the legacy `chuli.py`
  merge script still works.

Saved response bodies live in `<out>/<target>/response/` (only kept when
`Probe.Kept == true`).

## Status

- Phase 1: skeleton + HTTP fetcher + crawler + JSONL — done.
- Phase 2: probe + rules engine + xlsx — done.
- Phase 3: chromedp headless + resume — done.
- Phase 4: Aho-Corasick on 3 hot paths + new framework patterns + pprof — done.
- Phase 5: tier-union extractor + chunked streaming + golden tests + docs + release CI — done.
- **v0.4.0**: framework-aware extraction, HaE rule set merge, user-editable
  rules.yaml, Python-parity URL permutation, ancestor probing, action-aware
  fan-out, combined XLSX, quiet logging — done.

### v0.4.0 specifics

- **Framework-aware extractor**
  (`internal/extractor/{baseurl,methodpair,routes}.go`):
  - `DetectBaseURLs` finds every `axios.create({baseURL:"…"})`,
    `.defaults.baseURL=…`, minified `o().create({…})`, and
    `Vue.prototype.$x = axios.create(…)` form. The regexes are
    nested-brace aware so `headers:{…}` between `{` and `baseURL`
    doesn't break detection.
  - `DetectMethodPairs` finds `url:"X", method:"Y"` and the reverse,
    feeding declared verbs straight into the prober.
  - `DetectRoutes` finds Vue Router route blocks
    (`{path:"X", name:"Y", component:Z}`); matches are reclassified
    out of api_path emission BEFORE the baseURL prefix is applied,
    then routed to a dedicated XLSX sheet. Routes are never sent to
    the probe stage (the three-method fan-out against a 404 SPA shell
    is pure noise).

- **HaE rule set merge**: `scripts/fetch_hae_rules.sh` pulls the upstream
  HaE `Rules.yml` and converts it to jsscango's schema. The merged set
  is committed at `internal/rules/embedded/rules.yaml`. Rules from HaE
  whose patterns rely on RE2-unsupported features (Perl lookahead,
  Java-style `\u` escapes) are dropped during conversion.

- **User-editable rules at runtime**: `<UserConfigDir>/jsscango/rules.yaml`
  is auto-created on first scan; subsequent edits take effect immediately
  without rebuilding. Precedence: `--rules` > `$JSSCANGO_RULES_PATH` >
  user file > embedded. A malformed user file degrades to embedded
  rather than bricking the loader. `jsscango rules path` prints the
  resolved layer; `jsscango rules reset` restores the file from
  embedded defaults.

- **Python-parity probe URL permutation**
  (`internal/pipeline/permutate.go`): reproduces `getJsUrl.py:filter_data`.
  Derives `tree_urls` (scheme+host of every same-baseDomain chromedp seed),
  `base_urls` (truncation inference: seed `/dddd/eee/fff` + JS path
  `/eee/fff` → base `/dddd`), `path_with_api_urls` (seeds containing
  `api/`), splits extracted apiPaths on `api/` into `path_with_api_paths`
  + `path_with_no_api_paths`, then Cartesian over all of them. The
  `/api` fallback (Python's last-resort prefix when no extracted path
  contains `api/`) is gated to single-target `-u` mode — `-f` batches
  don't spray it across N hosts. Same-baseDomain filter, URL length cap,
  `//`-collapse, dedup. `--permutate-probe=false` reverts to single-base
  behavior.

- **Ancestor probing** (`internal/probe/ancestor.go`): for each 2xx
  `Probe.Kept` result, ascend up to `--ancestor-recurse-depth=2` parent
  paths and probe them as index endpoints (GET-only). Recursion-on-
  recursion is prevented; the depth is from the original hit in one
  shot, not a snake. Permutate-source hits also seed ancestor recurse.

- **Action-aware method fan-out** (`internal/probe/probe.go`): when no
  hint is declared, GET is always sent; POST_JSON only when the URL
  path tokenizes to contain a state-changing verb (`create`, `add`,
  `insert`, `update`, `delete`, `save`, `submit`, `login`, `logout`,
  …). Host-side action words are ignored (path-only matching). Cuts
  probe traffic ~57% on typical Vue/Ruoyi targets vs the legacy
  GET+POST_FORM+POST_JSON triple. `--probe-fanout=all` reverts to the
  legacy default; `--probe-fanout=conservative` is GET-only.

- **Quiet default output**: stderr only receives WARN+ slog records;
  full INFO/DEBUG streams to `<out>/scan.log` (auto-derived; override
  with `--log-file=<path>` or `--log-file=stderr`). The progress
  tracker owns the interactive window. `--verbose` lifts stderr to
  `--log-level` for debugging.

### Phase 5 specifics

- **Tier-union extractor** (`internal/extractor/union.go`) compiles the four
  pattern tiers (extras, JS, static, API) into one regex each, so each tier
  scans the body in a single pass instead of running each sub-pattern
  individually. Tiers run in priority order (extras > js > static > api) so
  dedup keeps the more specific pattern ID. Cross-tier union was rejected
  because RE2's leftmost-first lets a generic pattern starting one byte
  earlier outrank a more-specific extras pattern.

- **Chunked streaming for large bodies** — bodies under 4 MiB are scanned
  whole; larger bodies are split into 1 MiB windows with 16 KiB overlap.
  The overlap exceeds the longest possible regex match (~250 chars from
  the API patterns) so no match is lost at a chunk boundary.

- **Golden tests** (`internal/extractor/golden_test.go` +
  `internal/extractor/testdata/`) lock in the extractor's output on three
  realistic fixtures (webpack runtime, Vue inline-script, modern-framework
  blend). Run `go test -run TestGolden -update ./internal/extractor/` to
  rebaseline after an intentional change.

- **JSONL consumer guide** at [`docs/jsonl-consumer.md`](docs/jsonl-consumer.md)
  — schema reference plus jq recipes for the common questions ("show every
  kept probe URL", "count rule hits by kind", etc.), with bash and
  PowerShell variants.

- **Release CI** — `make release` cross-compiles for six targets
  (linux/darwin/windows × amd64/arm64) with
  `-trimpath -ldflags="-s -w -X main.version=…"` for reproducible builds.
  `.github/workflows/ci.yml` runs vet+build+race-tests on every push;
  `.github/workflows/release.yml` fires on `v*` tags, builds the six
  binaries, computes SHA256, and uploads to a GitHub release.

### Phase 4 specifics

- **Aho-Corasick** (`internal/util/aho`) replaces three linear "any-of-N" scans:
  the 246-entry MIME literal blacklist, the 21-entry URL substring blacklist,
  and the 68-entry BLACK_TEXT response-body marker list. The matcher is built
  once per process / per rule load. Benchmark vs `strings.Contains` shows a
  ~1.7× win on a small-pattern / known-hit corpus; on the more typical
  "no-marker present" case the speedup is larger because we walk the body
  once rather than N times.

- **New URL-discovery patterns** (`internal/extractor/patterns_extra.go`)
  add 10 framework-specific endpoint shapes to the generic JS/static/API
  regexes:

  | ID | What it catches |
  |---|---|
  | `swagger_doc` / `openapi_yaml` | Swagger UI + OpenAPI 3.x descriptors |
  | `graphql_ep` | `/graphql`, `/gql`, `/api/graphql` |
  | `sourcemap_ref` | `//# sourceMappingURL=…` references |
  | `actuator_endpoint` | Spring Boot Actuator paths |
  | `eureka_endpoint` | Spring Cloud Eureka apps API |
  | `vite_manifest` | Vite build asset map |
  | `nuxt_chunks` | Nuxt 3 `_nuxt/…` bundle URLs |
  | `nextjs_build` | Next.js build-ID-bearing manifest URLs |
  | `rpc_scheme` | `grpc://`, `dubbo://`, `nacos://`, … |
  | `internal_host` | localhost / RFC1918 / `*.internal` etc. |

  Extras run before the generic regexes so dedup keeps the more specific
  pattern ID for diagnostics.

- **pprof** is opt-in via `--pprof :6060`. Disabled by default; when on,
  the standard `/debug/pprof/*` handlers are served on the given address.

`--chrome=auto` (default) uses chromedp when a Chrome/Chromium binary is on
PATH, otherwise falls back to the static HTML homepage parser. Use
`--chrome=on` to require it, `--chrome=off` to disable.

`--resume` reads `results/<target>/state.json` and skips any stage already
completed. Use it to recover after Ctrl-C or to re-run only the parts that
failed (e.g. delete `state.json`'s `probe` flag and re-run with `--resume`
to redo probing only).

## License

MIT. See LICENSE.
