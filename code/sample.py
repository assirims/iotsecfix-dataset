"""Seeded, project-stratified random sample of tier-C candidates for manual labelling (R10c).

Writes data/validation_sample.csv with blank `label` and `notes`. Never overwrites a file that
already contains labels. Usage: python code/sample.py [n=200]
"""
import csv
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED = 20261025


def allocate(sizes: dict[str, int], n: int) -> dict[str, int]:
    """Proportional allocation with largest remainders; at least 1 per non-empty stratum."""
    total = sum(sizes.values())
    if n >= total:
        return dict(sizes)
    raw = {k: n * v / total for k, v in sizes.items()}
    out = {k: min(sizes[k], max(1 if sizes[k] else 0, int(r))) for k, r in raw.items()}
    rest = sorted(sizes, key=lambda k: (raw[k] - int(raw[k]), k), reverse=True)
    i = 0
    while sum(out.values()) < n:
        k = rest[i % len(rest)]
        if out[k] < sizes[k]:
            out[k] += 1
        i += 1
    while sum(out.values()) > n:  # minimum-1 rule can overshoot
        k = max(out, key=lambda k: out[k])
        out[k] -= 1
    return out


def main_ab(n_per_tier: int = 50) -> None:
    """Seeded sample of tier-A-only and tier-B (incl. A;B) records for link precision."""
    out = ROOT / "data/validation_sample_ab.csv"
    if out.exists() and any(r["label"].strip() for r in csv.DictReader(open(out))):
        sys.exit(f"{out} already has labels; not overwriting")
    fixes = json.loads((ROOT / "data/release/iotsecfix_fixes.json").read_text())
    rng = random.Random(SEED + 1)
    rows = []
    for tier, pool in (("A", [f for f in fixes if f["tiers"] == "A"]),
                       ("B", [f for f in fixes if "B" in f["tiers"]])):
        pool = sorted(pool, key=lambda f: (f["vuln_id"], f["fix_commit"]))
        rows += [(tier, f) for f in rng.sample(pool, min(n_per_tier, len(pool)))]
    rng.shuffle(rows)
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sample_id", "stratum", "project", "vuln_id", "advisory_url", "commit_url",
                    "change_scope", "label", "notes"])
        for i, (tier, f) in enumerate(rows, 1):
            adv = f["nvd_url"] or (f"https://github.com/{f['repo']}/security/advisories/{f['ghsa_id']}"
                                   if f["id_linked_to_project"] and f["ghsa_id"] else
                                   f"https://github.com/advisories/{f['vuln_id']}")
            w.writerow([i, tier, f["project"], f["vuln_id"], adv, f["commit_url"],
                        f["change_scope"], "", ""])
    print(f"wrote {len(rows)} rows to {out}")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "ab":
        return main_ab()
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    out = ROOT / "data/validation_sample.csv"
    if out.exists() and any(r["label"].strip() for r in csv.DictReader(open(out))):
        sys.exit(f"{out} already has labels; not overwriting")
    cands = json.loads((ROOT / "data/release/iotsecfix_candidates.json").read_text())
    by = {}
    for c in cands:
        by.setdefault(c["project"], []).append(c)
    rng = random.Random(SEED)
    rows = []
    for p, k in sorted(allocate({p: len(v) for p, v in by.items()}, n).items()):
        pool = sorted(by[p], key=lambda c: c["commit"])
        rows += rng.sample(pool, k)
    rng.shuffle(rows)
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sample_id", "project", "commit_url", "keywords", "subject", "label", "notes"])
        for i, c in enumerate(rows, 1):
            w.writerow([i, c["project"], c["commit_url"], c["keywords"], c["subject"], "", ""])
    print(f"wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
