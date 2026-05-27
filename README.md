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
- **Auto-tune** (v0.4.1+): on startup the tool reads the host's CPU count
  and RAM, then picks a tier from a baked-in table that sets sensible
  workers / per-host-qps / parallelism. Explicit flags always win.
- **Liveness pre-probe** (v0.4.1+): before the main pipeline, `-f` batches
  with > 50 targets run a concurrent HEAD/GET sweep and drop the dead
  hosts so probe budget isn't wasted on refused/timeout/DNS-fail entries.
- **Concurrent targets** (v0.4.1+): `-f` runs N targets in parallel
  (default from the tier). JSONL collapses to a single combined file
  with Target column; per-target subdirs still hold response bodies.
- **CSV output** (v0.4.1+): `--format csv` writes three flat streaming
  files (`probes.csv`, `fingerprints.csv`, `sensitive.csv`) at the
  output root. Auto-selected at medium-and-up tiers since XLSX's
  in-memory model doesn't scale to tens of thousands of targets.
- **Live progress** (v0.4.1+): on a TTY, a two-row block at the bottom
  of stderr shows scan-level progress (`存活 alive/total  完成 done/alive`
  with percentages) plus the current stage's per-counter spinner.

## Install

Prebuilt binaries for linux/darwin/windows × amd64/arm64 are attached to
each GitHub release: <https://github.com/dogadmin/jsscango/releases>.

```sh
# example: pick the Linux amd64 binary and put it on PATH
wget https://github.com/dogadmin/jsscango/releases/latest/download/jsscango_linux_amd64
chmod +x jsscango_linux_amd64
sudo mv jsscango_linux_amd64 /usr/local/bin/jsscango
```

Or build from source (Go 1.22+):

```sh
go build -o jsscango ./cmd/getjsurlscan
```

### Linux headless-Chrome runtime deps (required for `--chrome=on/auto`)

On a fresh server image the bundled Chromium needs a handful of shared
libraries. Install them BEFORE the first scan — otherwise every target
will warn `libgbm.so.1: cannot open shared object file`. Skip this step
only if you plan to run with `--chrome=off`.

```sh
# Ubuntu 24.04+ (the t64 suffix is the time_t-64-bit transition)
apt install -y libgbm1 libnss3 libasound2t64 libxkbcommon0 libxcomposite1 \
               libxdamage1 libxfixes3 libxrandr2 libxshmfence1 libdrm2 \
               libpangocairo-1.0-0 libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64

# Debian 12 / Ubuntu 22.04 (no t64 suffix)
apt install -y libgbm1 libnss3 libasound2 libxkbcommon0 libxcomposite1 \
               libxdamage1 libxfixes3 libxrandr2 libxshmfence1 libdrm2 \
               libpangocairo-1.0-0 libatk1.0-0 libatk-bridge2.0-0 libcups2

# CentOS / RHEL / Rocky / Alma
yum install -y nss alsa-lib mesa-libgbm libXcomposite libXdamage libXrandr \
               libxshmfence pango cups-libs at-spi2-atk
```

macOS and Windows already ship the graphics stack — no extra install
needed. If you can't or don't want to install the deps, pass
`--chrome=off` and the tool will fall back to static `<script src>`
parsing (still recovers 90% of read-only JS scan signal).

## Usage

### Quick start

```sh
# one URL, defaults handle everything (auto-tune, action-aware fan-out, etc.)
jsscango scan -u https://example.com/

# tens of thousands from a file — auto-tune picks the tier, liveness
# drops dead hosts, CSV replaces XLSX, N targets run in parallel.
jsscango scan -f targets.txt
```

That's the intended invocation at scale — every other knob below is for
deviations from the defaults.

### What you'll see on the terminal

```
log: results/scan.log
tune: big  workers=128 workers-probe=256 per-host-qps=15 concurrent-targets=8
liveness: 2104/2851 alive, 747 dead
  存活 2104/2851 (73.8%)  完成 42/2104 (2.0%)
⠹ [probe] elapsed=18.3s urls=1419 js=9 api_paths=856 probes=2120 probes_kept=3
```

- **`log:`** — full INFO/DEBUG trail; stderr only carries WARN+.
- **`tune:`** — the resolved auto-tune tier and the values it applied.
- **`liveness:`** — alive vs total after the pre-probe (`-f` batches > 50).
- **Top row of the live block** — scan-level: alive count, completed count,
  percentages. Updates as targets finish.
- **Bottom row** — current stage + counters, refreshed ~8 Hz.

The live block disappears with `--no-progress` or when stderr isn't a TTY.

### Common scenarios

```sh
# 1. Single target, default behaviour. Auto-tune kicks in;
#    JSONL + XLSX written under results/.
jsscango scan -u https://example.com/

# 2. Batch from file. Liveness pre-probe filters dead hosts;
#    CSV format auto-selected at medium-and-up tiers.
jsscango scan -f targets.txt

# 3. Pin a tier explicitly. Useful inside a CI worker with known specs.
jsscango scan -f targets.txt --tune=big

# 4. Probe a single page, don't actually send requests.
jsscango scan -u https://example.com/ --no-probe

# 5. Use your own rules file. The auto-materialised
#    ~/.config/jsscango/rules.yaml is also editable.
jsscango scan -u https://example.com/ --rules my-rules.yaml

# 6. Pull cookies from a logged-in browser session.
jsscango scan -u https://intranet.example.com/ -c "session=abc; auth=xyz"

# 7. Headless Chrome off — fall back to static <script src> parsing.
#    Useful on minimal Linux without the X11 deps installed.
jsscango scan -u https://example.com/ --chrome=off

# 8. Resume an interrupted run. Each stage marks itself done in
#    state.json; --resume picks up where the last invocation died.
jsscango scan -u https://example.com/ --resume

# 9. Aggressive: bypass the tier defaults and push throughput.
jsscango scan -f targets.txt --tune=off --concurrent-targets=32 \
    --workers-probe=512 --per-host-qps=50

# 10. Inspect what auto-tune chose without actually scanning.
jsscango scan -f targets.txt --show-tune

# 11. CSV only (no JSONL, no XLSX) at any scale.
jsscango scan -f targets.txt --format csv

# 12. Force a per-target XLSX (legacy layout). Incompatible with parallel
#     targets — the CLI rejects --xlsx-split --concurrent-targets > 1.
jsscango scan -u https://example.com/ --xlsx-split
```

Run `jsscango scan --help` for the complete flag list.

### Auto-tune (`--tune`)

On startup the tool detects logical CPU count and total RAM, then picks
the strongest tier the host satisfies. Tiers preset Workers / Crawl /
Probe / per-host QPS / Concurrent-Targets.

| Tier         | CPU | RAM   | workers | probe | qps  | parallel |
| ------------ | --- | ----- | ------- | ----- | ---- | -------- |
| `tiny`       | 1   | 1 GiB | 16      | 32    | 3    | 1        |
| `small`      | 2   | 2 GiB | 32      | 64    | 5    | 2        |
| `small-fat`  | 2   | 4 GiB | 48      | 96    | 5    | 2        |
| `medium`     | 4   | 4 GiB | 64      | 128   | 8    | 4        |
| `medium-fat` | 4   | 8 GiB | 96      | 192   | 10   | 4        |
| `big`        | 8   | 8 GiB | 128     | 256   | 15   | 8        |
| `big-fat`    | 8   | 16 GiB| 192     | 384   | 20   | 8        |
| `huge`       | 16  | 16 GiB| 256     | 512   | 25   | 16       |
| `huge-fat`   | 16  | 32 GiB| 384     | 768   | 30   | 16       |

Flags that interact with auto-tune:

| Flag                  | Effect                                                |
| --------------------- | ----------------------------------------------------- |
| `--tune=auto`         | Default; detect tier from host                        |
| `--tune=<name>`       | Pin a tier (e.g. `--tune=big`)                        |
| `--tune=off`          | Honour `--workers` / `--per-host-qps` / etc. verbatim |
| `--show-tune`         | Print the resolved tier values and exit               |

Any flag the operator passes overrides the tier's value for that field.
The check compares against `config.Default()` — leave a flag unset to
let auto-tune fill it in.

At `medium` and above, auto-tune also flips the default `--format` from
`jsonl,xlsx` to `jsonl,csv` (XLSX's in-memory buffering becomes a
liability at scale). Explicit `--format` is honoured.

### Liveness pre-probe (`--liveness-check`)

For `-f` batches the tool runs a short concurrent HEAD/GET pre-pass to
drop hosts that won't respond at all (refused / DNS fail / dial timeout
/ TLS error). Anything that returns ANY HTTP code counts as alive,
including 401/403/5xx — the host being up is the only criterion.

| Flag                          | Default | What                                    |
| ----------------------------- | ------- | --------------------------------------- |
| `--liveness-check=auto`       | auto    | Enabled when len(targets) > threshold   |
| `--liveness-check=on/off`     | —       | Force on/off                            |
| `--liveness-timeout=3s`       | 3s      | Per-URL ceiling                         |
| `--liveness-workers=128`      | 128     | Concurrent probes                       |
| `--liveness-auto-threshold=50`| 50      | `auto` threshold                        |

Dead targets' reasons go to `<out>/scan.log` (INFO level) so the
progress window stays clean; the stderr summary just shows
`liveness: N/M alive, K dead`.

### Output formats (`--format`)

Comma-separated list, any subset of `jsonl|xlsx|csv`.

| Format  | Path(s)                                                  | When to use                                                                                |
| ------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `jsonl` | `<out>/[<target>/]report.jsonl`                          | Streaming; programmatic consumers (jq, scripts). Combined into one file when ≥ 2 parallel. |
| `xlsx`  | `<out>/report.xlsx`                                      | Interactive review of small batches (≤ small-fat tier). 10 sheets, `Target` column.        |
| `csv`   | `<out>/probes.csv` `fingerprints.csv` `sensitive.csv`    | Tens-of-thousands-of-targets scale. Streaming, tiny memory footprint, grep/awk-friendly.   |

CSV columns:

- **`probes.csv`** — `Target | URL | Method | Status | Content-Type | Size | Body Path | SHA256 | Source` (only kept 2xx-JSON/XML probes).
- **`fingerprints.csv`** — `Target | Rule ID | Kind | Group | Matches | File | URL` (fingerprint + vuln rule hits).
- **`sensitive.csv`** — `Target | Rule ID | Group | Matches | File | URL` (sensitive rule hits only).

Each CSV opens with `O_APPEND` so `--resume` doesn't double the header.

### Output directory layout

```
results/
├── report.jsonl                     # combined when --concurrent-targets > 1
├── report.xlsx                      # combined; one Target column per sheet
├── probes.csv                       # only when --format includes csv
├── fingerprints.csv                 # ditto
├── sensitive.csv                    # ditto
├── scan.log                         # full INFO/DEBUG trail
├── <target1-folder>/
│   ├── report.jsonl                 # only when --concurrent-targets == 1
│   ├── state.json                   # resume cursor
│   └── response/                    # saved 2xx bodies (one per kept probe)
└── <target2-folder>/
    └── ...
```

Saved response bodies live in `<out>/<target>/response/` (only kept when
`Probe.Kept == true`).

### Rules management

```sh
# Where will the loader read rules from? Prints the precedence chain.
jsscango rules path

# Reset the user-config rules.yaml back to the embedded baseline.
jsscango rules reset

# List all currently-loaded rule IDs, grouped by kind.
jsscango rules list

# Validate a YAML file without running a scan.
jsscango rules validate ./my-rules.yaml

# Print the embedded defaults so you can adapt them.
jsscango rules dump --out ./my-rules-base.yaml
```

Precedence (highest first):

1. `--rules <path>` CLI flag — hard override; parse failure is fatal.
2. `$JSSCANGO_RULES_PATH` env var — same fatal semantics.
3. `<user-config-dir>/jsscango/rules.yaml` — auto-materialised on first
   scan. Malformed → falls back to embedded with a warning.
4. Embedded defaults compiled into the binary.

User-config dir per platform: `%APPDATA%\jsscango\` on Windows,
`~/.config/jsscango/` on Linux, `~/Library/Application Support/jsscango/`
on macOS.

### Resume

`--resume` reads `results/<target>/state.json` and skips any stage already
completed. Use it to recover after Ctrl-C or to re-run only the parts
that failed (e.g. delete `state.json`'s `probe` flag and re-run with
`--resume` to redo probing only).

### Headless Chrome

`--chrome=auto` (default) uses chromedp when a Chrome/Chromium binary is
on PATH, otherwise falls back to the static HTML homepage parser. Use
`--chrome=on` to require it, `--chrome=off` to disable.

The bundled Chromium needs Linux runtime libraries to start — see
[Linux headless-Chrome runtime deps](#linux-headless-chrome-runtime-deps-required-for---chromeonauto)
in the Install section above. macOS and Windows have the graphics stack
preinstalled.

## Status

- Phase 1: skeleton + HTTP fetcher + crawler + JSONL — done.
- Phase 2: probe + rules engine + xlsx — done.
- Phase 3: chromedp headless + resume — done.
- Phase 4: Aho-Corasick on 3 hot paths + new framework patterns + pprof — done.
- Phase 5: tier-union extractor + chunked streaming + golden tests + docs + release CI — done.
- **v0.4.0**: framework-aware extraction, HaE rule set merge, user-editable
  rules.yaml, Python-parity URL permutation, ancestor probing, action-aware
  fan-out, combined XLSX, quiet logging — done.
- **v0.4.1**: auto-tune by CPU/RAM (9 tiers), liveness pre-probe for
  `-f` batches, concurrent-targets (parallel `-f` target processing),
  CSV format (three streaming files), live two-row progress block with
  alive/done/total + percentages, plus two review passes on the v0.4.0
  batch (21 findings landed) — done.

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

## License

MIT. See LICENSE.
