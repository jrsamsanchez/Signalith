#!/usr/bin/env bash
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Writes llms-full.txt: site/llms.txt followed by every documentation page, in
# the order of the nav in mkdocs.yml, as plain Markdown, for AI assistants and
# search tools that read a whole site in one file (https://llmstxt.org).
#   .github/scripts/llms-full.sh <output file>
set -euo pipefail
out=${1:?usage: llms-full.sh <output file>}
cd "$(dirname "$0")/../.."
{
  cat site/llms.txt
  # Pages listed in the nav, each once, in nav order.
  sed -n '/^nav:/,$p' mkdocs.yml | grep -oE '[A-Za-z0-9_./-]+\.md' | awk '!seen[$0]++' |
  while read -r page; do
    [ -f "docs/$page" ] || { echo "llms-full.sh: docs/$page is in the nav but missing" >&2; exit 1; }
    url=${page%.md}/
    [ "$page" = index.md ] && url=
    printf '\n\n---\n\nSource: https://signalith.io/docs/%s\n\n' "$url"
    # Drop the YAML front matter at the top of a page.
    awk 'NR==1 && /^---$/ {fm=1; next} fm && /^---$/ {fm=0; next} !fm' "docs/$page"
  done
} >"$out"
