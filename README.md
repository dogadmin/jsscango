# jsscango

JavaScript / static URL / API endpoint scanner. A Go rewrite of the Python
`getjsurlscan` tool, optimised for throughput, accuracy, and a clean
machine-readable output format.

## What it does

Given a list of target URLs, jsscango walks the site's JavaScript bundles to
discover hidden API paths, then optionally probes those endpoints (GET +
POST form + POST JSON) and scans the responses for sensitive data leaks
(JWT, cloud access keys, webhooks, internal IPs, etc.).

5 stages per target:

| # | Stage | What |
|---|---|---|
| 1 | homepage | Parse `<script src>` from the target page (static) or capture network events from a headless browser (chromedp, Phase 3). |
| 2 | crawl | BFS the JS files found in stage 1, extracting more JS, static, and API path candidates. Bounded by `--max-depth`. |
| 3 | api-path | Filter candidates through regex + structural false-positive predicates. |
| 4 | probe | Send GET/POST_FORM/POST_JSON to each candidate, keeping only `200 + json/xml + !blacktext` responses. Dangerous endpoints (`delete`, `logout`, …) are skipped. |
| 5 | postprocess | Apply the rule set to every saved response body, emitting fingerprint / vuln / sensitive hits. |

## Differences vs the Python original

- **Concurrency**: per-stage worker pools (`errgroup` + `semaphore`) instead of
  300 raw threads per stage with `time.sleep(0.2)` stagger. Per-host token
  bucket rate limit (`golang.org/x/time/rate`) prevents hammering a single
  backend.
- **HTTP**: single `*http.Client` with HTTP/2 + connection reuse + retry with
  jitter; body size bounded by `--max-body-mb`.
- **Dedup**: response-body SHA256 dedup at probe time, not as a post-hoc step.
- **Safety**: replaces the Python tool's `eval(response_body)` parameter
  miner (RCE risk) with `json.Unmarshal` plus regex.
- **Rules**: 50 regex rules + 68 blacktext markers, all embedded via
  `go:embed`. Override with `--rules path/to/rules.yaml`.
- **Output**: streaming JSONL plus multi-sheet XLSX, both written from the
  same event stream.
- **Crawl depth**: BFS bounded by `--max-depth` (default 3) so cyclic
  webpack imports terminate.

## Build

```sh
go build -o jsscango ./cmd/getjsurlscan
```

Requires Go 1.22+.

## Usage

```sh
# scan a single target
jsscango scan -u https://example.com/

# scan from a file (one URL per line)
jsscango scan -f targets.txt --workers 32 --per-host-qps 5

# collect URLs only, no probing
jsscango scan -u https://example.com/ --no-probe

# use external rules
jsscango scan -u https://example.com/ --rules my-rules.yaml
```

Run `jsscango scan --help` for the full flag list.

## Output

Per target, two files under `results/<sanitized-target>/`:

- **`report.jsonl`** — one JSON object per line. Events:
  `stage`, `discovered_url`, `api_path`, `probe`, `rule_hit`, `summary`.
- **`report.xlsx`** — 9 sheets, names matching the original Python tool
  (so the legacy `chuli.py` merge script still works).

Saved response bodies live in `results/<target>/response/` (only kept
when `Probe.Kept == true`).

## Status

- Phase 1: skeleton + HTTP fetcher + crawler + JSONL — done.
- Phase 2: probe + rules engine + xlsx — done.
- Phase 3: chromedp headless + resume — done.
- Phase 4: Aho-Corasick on 3 hot paths + new framework patterns + pprof — done.
- Phase 5 (deferred): union regex single-pass extractor + streaming bodies for >4 MiB.

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
