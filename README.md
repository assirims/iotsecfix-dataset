# IoTSecFix 1.0.0 — security-fixing commits in open-source IoT software

Snapshot date: 2026-10-25. Companion to the MSR 2027 Data and Tool Showcase paper
"IoTSecFix: A Curated Dataset of Security-Fixing Commits in Open-Source IoT Software".

## Contents
- `data/release/` — `iotsecfix_fixes.{csv,json}` (tiers A/B), `iotsecfix_candidates.{csv,json}`
  (tier C, unvalidated), JSON Schemas, `DATASHEET.md`; labelled samples `data/validation_sample.csv`
  (tier C) and `data/validation_sample_ab.csv` (tiers A/B), labelled by Claude (LLM), see `data/labeller.txt`.
- `code/` — collection and analysis scripts with unit tests; `projects.json` = project pool.
- `PROTOCOL.md` — selection rules, sources, linking rules, deviations.
- `results/results.json` — every number in the paper.

## Quick start
```python
import pandas as pd
d = pd.read_csv("data/release/iotsecfix_fixes.csv")
core = d[d.change_scope == "code"]           # drop doc/CI-only and test-only links
core = core[core.id_linked_to_project & core.on_default_branch & (core.pr_commits.fillna(1) <= 1)]  # high confidence
```
Field definitions: `data/release/iotsecfix_fixes.schema.json`.

## Rebuild a snapshot (Python 3.12, git, GitHub CLI `gh` logged in)
```
pip install -r requirements.txt
python code/nvd_fetch.py data/raw/nvd      # full NVD via API 2.0 (keyless ~30-40 min; NVD_API_KEY optional)
python code/ghsa_fetch.py                  # repository security advisories via gh api
sh code/clone.sh                           # blobless clones (~0.8 GB) in data/raw/repos
python code/build_dataset.py               # writes data/release/*
python code/validate_release.py && python code/stats.py && python code/figures.py
python -m pytest code/tests
```
Scripts read/write paths relative to the package root (`data/release`, `data/raw`, `results`).

## Licenses
Code: MIT (`LICENSE`). Data: CC BY 4.0 (`LICENSE-DATA`). Upstream sources: NVD data is a U.S.
government work (public domain); GitHub repository advisories are public; commit metadata
comes from the listed public repositories. No author names or e-mails of commits are included.

## Citation
See `CITATION.cff`.
