"""Merge review/labelling/*_labels.csv into the two validation samples.

The labels were produced by Claude (Anthropic) subagents at the author's request (25 Oct 2026,
"you do it"), one subagent per 50-row chunk, from the evidence bundles of code/label_bundle.py.
Writes the `label` and `notes` columns and data/labeller.txt. Usage: python code/merge_labels.py
"""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "review/labelling"
VALID = {"c": {"security_fix", "not_security_fix", "unsure"},
         "ab": {"fixes_vulnerability", "part_of_fix", "not_fix", "unsure"}}


def merge(name: str, target: Path) -> None:
    labels = {}
    for f in sorted(LAB.glob(f"{name}_*_labels.csv")):
        for r in csv.DictReader(open(f)):
            lab = r["label"].strip()
            assert lab in VALID[name], (f, r)
            labels[r["sample_id"].strip()] = (lab, r.get("notes", "").strip())
    rows = list(csv.DictReader(open(target)))
    missing = [r["sample_id"] for r in rows if r["sample_id"] not in labels]
    assert not missing, f"{target.name}: no label for {missing}"
    scope = {}
    if name == "ab":  # refresh change_scope from the current release (classifier may be updated)
        scope = {(f["vuln_id"], f["fix_commit"]): f["change_scope"] for f in
                 json.loads((ROOT / "data/release/iotsecfix_fixes.json").read_text())}
    for r in rows:
        r["label"], r["notes"] = labels[r["sample_id"]]
        if scope:
            r["change_scope"] = scope[(r["vuln_id"], r["commit_url"].rsplit("/", 1)[1])]
    with open(target, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(target.name, len(rows), "labelled")


merge("c", ROOT / "data/validation_sample.csv")
merge("ab", ROOT / "data/validation_sample_ab.csv")
lf = ROOT / "data/labeller.txt"
if not lf.exists():  # the author's review status is recorded in this file by hand afterwards
    lf.write_text("Claude (Anthropic), single LLM rater, not checked by a human\n")
