#!/usr/bin/env bash
# fetch_hae_rules.sh
#
# Refresh internal/rules/embedded/rules.yaml from the upstream HaE Burp
# extension config (https://github.com/gh0stkey/HaE). Run from anywhere; the
# script cd's to the repo root via its own location.
#
# What it does:
#   1. Downloads HaE's latest Rules.yml from main.
#   2. Runs scripts/_hae_converter.go which converts the HaE schema into our
#      rules.yaml schema, merges with any rules we have that HaE doesn't, and
#      emits a 2-space-indented YAML to a working dir.
#   3. Overwrites internal/rules/embedded/rules.yaml in place.
#   4. Runs `go test ./internal/rules/...` to sanity-check.
#
# This script is not idempotent in the sense that re-running it will produce
# fresh output every time — that's the point. The next maintainer can review
# the resulting diff and commit it.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d -t hae_rules_XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

cd "$work_dir"

# 1. Fetch HaE Config. The path inside HaE has moved a few times; try the
#    canonical one first, then a couple of fallbacks before giving up.
hae_urls=(
  "https://raw.githubusercontent.com/gh0stkey/HaE/main/src/HaENet/src/main/resources/rules/Rules.yml"
  "https://raw.githubusercontent.com/gh0stkey/HaE/master/Config.yml"
  "https://raw.githubusercontent.com/gh0stkey/HaE/main/Config.yml"
)
ok=0
for url in "${hae_urls[@]}"; do
  code="$(curl -sk -o hae_config.yml -w "%{http_code}" "$url" || true)"
  if [[ "$code" == "200" ]]; then
    echo "fetched HaE config from $url"
    ok=1
    break
  fi
done
if [[ "$ok" -ne 1 ]]; then
  echo "could not fetch HaE Config.yml from any known URL" >&2
  exit 1
fi

# 2. Run the converter Go program against our existing rules.yaml.
cp "$repo_root/scripts/_hae_converter.go" converter.go
cp "$repo_root/internal/rules/embedded/rules.yaml" existing_rules.yaml
go mod init hae_converter >/dev/null 2>&1 || true
go mod tidy >/dev/null 2>&1
go run converter.go

# 3. Replace embedded rules.yaml.
cp rules_merged.yaml "$repo_root/internal/rules/embedded/rules.yaml"
echo "wrote $repo_root/internal/rules/embedded/rules.yaml"

# 4. Sanity check.
cd "$repo_root"
go test ./internal/rules/...
echo "done."
