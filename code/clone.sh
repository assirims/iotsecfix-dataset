#!/bin/sh
# Blobless clones of every candidate repo into data/raw/repos/<id> (gitignored).
# Re-running fetches updates. Usage: sh code/clone.sh
set -eu
cd "$(dirname "$0")/.."
PY=../shared/.venv/bin/python
$PY -c 'import json;[print(c["id"],c["repo"]) for c in json.load(open("code/projects.json"))["candidates"]]' |
while read id repo; do
  d=data/raw/repos/$id
  if [ -d "$d" ]; then git -C "$d" fetch -q origin; else
    git clone -q --filter=blob:none --no-checkout "https://github.com/$repo.git" "$d"; fi
  echo "$id $(git -C "$d" rev-parse HEAD) $(date -u +%Y-%m-%dT%H:%M:%SZ)"
done
