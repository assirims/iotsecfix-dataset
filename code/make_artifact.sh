#!/bin/sh
# Assemble the release package artifact/iotsecfix-1.0.0/ and its zip (no upload).
# Usage: sh code/make_artifact.sh
set -eu
cd "$(dirname "$0")/.."
OUT=artifact/iotsecfix-1.0.0
rm -rf "$OUT"; mkdir -p "$OUT/data/release" "$OUT/code/tests" "$OUT/results"
cp artifact_src/README.md artifact_src/LICENSE artifact_src/LICENSE-DATA artifact_src/CITATION.cff \
   artifact_src/.zenodo.json PROTOCOL.md requirements.txt "$OUT/"
cp data/release/*.csv data/release/*.json data/release/DATASHEET.md "$OUT/data/release/"
cp data/validation_sample.csv data/validation_sample_ab.csv data/labeller.txt \
   data/VALIDATION_INSTRUCTIONS.md "$OUT/data/"
cp code/*.py code/*.sh code/projects.json code/DATASHEET.template.md "$OUT/code/"
cp code/tests/*.py "$OUT/code/tests/"
cp results/results.json "$OUT/results/"
find "$OUT" -name '__pycache__' -prune -exec rm -rf {} +
(cd artifact && rm -f iotsecfix-1.0.0.zip && zip -qr iotsecfix-1.0.0.zip iotsecfix-1.0.0)
ls -la artifact/iotsecfix-1.0.0.zip
