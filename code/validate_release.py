"""Validate data/release/*.json against their JSON Schemas and check CSV/JSON row parity.

Usage: python code/validate_release.py
"""
import csv
import json
from pathlib import Path

import jsonschema

REL = Path(__file__).resolve().parent.parent / "data/release"

for stem in ("iotsecfix_fixes", "iotsecfix_candidates"):
    rows = json.loads((REL / f"{stem}.json").read_text())
    schema = json.loads((REL / f"{stem}.schema.json").read_text())
    jsonschema.validate(rows, schema, format_checker=jsonschema.FormatChecker())
    n_csv = sum(1 for _ in csv.DictReader(open(REL / f"{stem}.csv")))
    assert n_csv == len(rows), (stem, n_csv, len(rows))
    print(f"{stem}: {len(rows)} rows valid, CSV parity ok")
