# JSONL Consumer Guide

## Overview

`jsscango` streams every interesting thing it learns during a scan to a
newline-delimited JSON file (NDJSON / JSONL) — one self-contained JSON object
per line. The file lives at `results/<sanitized-target>/report.jsonl`, where
the directory segment is the target host (and port, if non-default) with
disk-unsafe characters replaced; a scan of `https://example.com/` writes
`results/example.com/report.jsonl`.

The file is opened in append mode, flushed periodically, and finalized on
shutdown — you can `tail -f` it during a long run, and partial runs remain
readable up to the last flushed line.

Events are emitted in roughly the order the scanner produces them:

| `event`           | Emitted when                                                                          |
|-------------------|---------------------------------------------------------------------------------------|
| `stage`           | A pipeline stage starts or ends (crawling, extracting, probing, postprocessing, etc.) |
| `discovered_url`  | The crawler or an extractor finds a new URL (HTML page, JS file, static asset).       |
| `api_path`        | An API path / endpoint pattern is mined out of a JS file or response body.            |
| `probe`           | The active prober finishes hitting a candidate URL and records the response.          |
| `rule_hit`        | A fingerprint, vuln signature, or sensitive-data rule fires.                          |
| `summary`         | Exactly one terminal line per scan with totals and timing.                            |

## Schema

Every line decodes to the same wrapper `Report`. The envelope always carries
`schema` (`getjsurlscan/v1`), `time` (RFC3339), `target`, and `event`. The
`event` discriminator selects exactly one sub-payload; the others are omitted.

| `event`           | Sub-field populated | Payload fields                                                                                                                |
|-------------------|---------------------|-------------------------------------------------------------------------------------------------------------------------------|
| `stage`           | `stage` (string)    | Free-form stage name (e.g. `crawl.start`, `probe.done`).                                                                      |
| `discovered_url`  | `discovered_url`    | `target`, `url`, `referer`, `kind`, `depth`, `source`. `kind` ∈ {`base_url`, `no_js`, `js`, `static_url`, `api_path`}.        |
| `api_path`        | `api_path`          | `target`, `referer`, `api_path`, `pattern`.                                                                                   |
| `probe`           | `probe`             | `target`, `url`, `method`, `status_code`, `content_type`, `size`, `body_path`, `referer`, `parameter`, `body_sha256`, `kept`, `duplicate`. |
| `rule_hit`        | `rule_hit`          | `target`, `kind` ∈ {`fingerprint`, `vuln`, `sensitive`}, `rule_id`, `group`, `matches` (string slice), `url`, `file`.         |
| `summary`         | `summary`           | `duration_ms`, `urls_discovered`, `js_fetched`, `api_paths`, `probes`, `rule_hits`, `stage_counts` (stage-name → count map).  |

## Event reference

### `stage`

Marks a stage boundary. Useful for timing phases and correlating later events.

```json
{"schema":"getjsurlscan/v1","time":"2026-05-27T10:14:02.117Z","target":"https://example.com/","event":"stage","stage":"crawl.start"}
```

### `discovered_url`

One line per *new* URL; repeated discoveries are deduplicated upstream.

```json
{"schema":"getjsurlscan/v1","time":"2026-05-27T10:14:03.842Z","target":"https://example.com/","event":"discovered_url","discovered_url":{"target":"https://example.com/","url":"https://example.com/static/app.bundle.7f3a91.js","referer":"https://example.com/","kind":"js","depth":1,"source":"html.script"}}
```

### `api_path`

Emitted when the API-path extractor mines an endpoint out of a JS file or
response body. `pattern` is the regex / heuristic name that fired.

```json
{"schema":"getjsurlscan/v1","time":"2026-05-27T10:14:05.011Z","target":"https://example.com/","event":"api_path","api_path":{"target":"https://example.com/","referer":"https://example.com/static/app.bundle.7f3a91.js","api_path":"/api/v2/users/profile","pattern":"axios.get"}}
```

### `probe`

One line per probe attempt, including duplicates (`kept: false`, possibly
`duplicate: true` when the body hash matches a previously kept response).

```json
{"schema":"getjsurlscan/v1","time":"2026-05-27T10:14:07.503Z","target":"https://example.com/","event":"probe","probe":{"target":"https://example.com/","url":"https://example.com/api/v2/users/profile","method":"GET","status_code":200,"content_type":"application/json; charset=utf-8","size":482,"body_path":"results/example.com/bodies/2a/2a8c1e0b9f.json","referer":"https://example.com/static/app.bundle.7f3a91.js","body_sha256":"2a8c1e0b9fbd4d6e0f2b8a13c8d9e07a2c5b71e3b8f2d4a6c8e0b1d3f5a7c9e1","kept":true}}
```

### `rule_hit`

`kind` is `fingerprint` (tech ID), `vuln` (known signature), or `sensitive`
(credentials, tokens, PII).

```json
{"schema":"getjsurlscan/v1","time":"2026-05-27T10:14:08.221Z","event":"rule_hit","target":"https://example.com/","rule_hit":{"target":"https://example.com/","kind":"sensitive","rule_id":"jwt.bearer","group":"tokens","matches":["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"],"url":"https://example.com/static/app.bundle.7f3a91.js","file":"results/example.com/js/app.bundle.7f3a91.js"}}
```

### `summary`

The last line of a complete run; totals across the whole scan.

```json
{"schema":"getjsurlscan/v1","time":"2026-05-27T10:14:31.902Z","target":"https://example.com/","event":"summary","summary":{"duration_ms":29785,"urls_discovered":412,"js_fetched":37,"api_paths":86,"probes":71,"rule_hits":14,"stage_counts":{"crawl":1,"extract":37,"probe":71,"postprocess":1}}}
```

## Recipes

All recipes assume the run wrote to `results/example.com/report.jsonl`.

### List all kept probe URLs

Which probes did the scanner keep (non-duplicate, interesting responses)?

```bash
jq -r 'select(.event == "probe" and .probe.kept == true) | .probe.url' \
  results/example.com/report.jsonl
```

```
https://example.com/api/v2/users/profile
https://example.com/api/v2/orders?id=1
https://example.com/.well-known/openid-configuration
```

### Count rule hits grouped by kind

How many fingerprint vs vuln vs sensitive hits did this run produce?

```bash
jq -r 'select(.event == "rule_hit") | .rule_hit.kind' \
  results/example.com/report.jsonl \
  | sort | uniq -c | sort -rn
```

```
   9 sensitive
   4 fingerprint
   1 vuln
```

### Extract just the JS URLs discovered

List every JS file the scanner found.

```bash
jq -r 'select(.event == "discovered_url" and .discovered_url.kind == "js")
       | .discovered_url.url' \
  results/example.com/report.jsonl
```

```
https://example.com/static/app.bundle.7f3a91.js
https://example.com/static/vendor.5d1b22.js
https://cdn.example.com/analytics/v3/loader.js
```

### Find probes that returned status 200 with JSON content type

Which endpoints answered 200 OK and look like JSON APIs?

```bash
jq -c 'select(.event == "probe"
              and .probe.status_code == 200
              and (.probe.content_type // "" | startswith("application/json")))
       | {url: .probe.url, size: .probe.size}' \
  results/example.com/report.jsonl
```

```
{"url":"https://example.com/api/v2/users/profile","size":482}
{"url":"https://example.com/api/v2/orders","size":1903}
```

### Dump all sensitive matches

Every individual sensitive value extracted, one per line.

```bash
jq -r 'select(.event == "rule_hit" and .rule_hit.kind == "sensitive")
       | .rule_hit.matches[]' \
  results/example.com/report.jsonl
```

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
AKIAIOSFODNN7EXAMPLE
sk_live_51HxYz2Lk4n8mQpRsTuVwXy
```

### Show the final summary line

Totals for this run.

```bash
jq -c 'select(.event == "summary") | .summary' \
  results/example.com/report.jsonl
```

```
{"duration_ms":29785,"urls_discovered":412,"js_fetched":37,"api_paths":86,"probes":71,"rule_hits":14,"stage_counts":{"crawl":1,"extract":37,"probe":71,"postprocess":1}}
```

## Cross-shell variants

On Windows / PowerShell you usually don't have `jq` handy. The native idiom is
`Get-Content | ConvertFrom-Json | Where-Object`.

### Kept probe URLs (PowerShell)

```powershell
Get-Content results/example.com/report.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.event -eq "probe" -and $_.probe.kept -eq $true } |
  ForEach-Object { $_.probe.url }
```

```
https://example.com/api/v2/users/profile
https://example.com/api/v2/orders?id=1
```

### Rule-hit counts by kind (PowerShell)

```powershell
Get-Content results/example.com/report.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.event -eq "rule_hit" } |
  Group-Object { $_.rule_hit.kind } |
  Sort-Object Count -Descending |
  Select-Object Count, Name
```

```
Count Name
----- ----
    9 sensitive
    4 fingerprint
    1 vuln
```

### Final summary line (PowerShell)

```powershell
Get-Content results/example.com/report.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.event -eq "summary" } |
  Select-Object -ExpandProperty summary
```

```
duration_ms     : 29785
urls_discovered : 412
js_fetched      : 37
api_paths       : 86
probes          : 71
rule_hits       : 14
```

## Combining multiple targets

Every line carries its own `target`, `schema`, and `time`, so you can simply
concatenate the per-target files and treat the result as one stream.

bash:

```bash
cat results/*/report.jsonl \
  | jq -r 'select(.event == "rule_hit" and .rule_hit.kind == "sensitive")
           | [.target, .rule_hit.rule_id, (.rule_hit.matches | length)] | @tsv'
```

```
https://example.com/      jwt.bearer       1
https://api.acme.test/    aws.access_key   2
https://shop.example.io/  stripe.live_key  1
```

PowerShell:

```powershell
Get-ChildItem results -Filter report.jsonl -Recurse |
  Get-Content |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.event -eq "rule_hit" -and $_.rule_hit.kind -eq "sensitive" } |
  Select-Object `
    @{n='target'; e={$_.target}},
    @{n='rule';   e={$_.rule_hit.rule_id}},
    @{n='count';  e={$_.rule_hit.matches.Count}}
```

Tip: for very large files, `Get-Content -Raw` + `-split "`n"` is much faster than per-line `ForEach-Object`.
