"""Evidence bundles for labelling the two validation samples.

For each row: commit message, changed-file list, first DIFF_LINES lines of the diff (from the
local clone), and for tier-A/B rows the vulnerability description (NVD, else GHSA).
Writes review/labelling/{c,ab}_<chunk>.md. Usage: python code/label_bundle.py [chunk=50]
"""
import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIFF_LINES = 120


def git(project: str, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(ROOT / "data/raw/repos" / project), *args],
                       capture_output=True, text=True, errors="replace")
    return r.stdout


def commit_text(project: str, sha: str) -> str:
    msg = git(project, "log", "-1", "--format=%B", sha).strip()
    stat = git(project, "show", "--stat=120", "--format=", sha).strip()
    diff = git(project, "show", "--format=", "--unified=2", sha).splitlines()
    more = f"\n... ({len(diff) - DIFF_LINES} more diff lines)" if len(diff) > DIFF_LINES else ""
    return f"MESSAGE:\n{msg}\n\nFILES:\n{stat}\n\nDIFF:\n" + "\n".join(diff[:DIFF_LINES]) + more


def descriptions(ids: set[str]) -> dict:
    out = {}
    for f in sorted((ROOT / "data/raw/nvd").glob("page_*.json")):
        for v in json.loads(f.read_text())["vulnerabilities"]:
            c = v["cve"]
            if c["id"] in ids:
                out[c["id"]] = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
    for f in (ROOT / "data/raw/ghsa").glob("*.json"):
        for a in json.loads(f.read_text())["advisories"]:
            for k in (a.get("cve_id"), a["ghsa_id"]):
                if k in ids and k not in out:
                    out[k] = (a.get("summary") or "") + "\n" + (a.get("description") or "")[:3000]
    return out


def main() -> None:
    chunk = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    out = ROOT / "review/labelling"
    out.mkdir(parents=True, exist_ok=True)
    c_rows = list(csv.DictReader(open(ROOT / "data/validation_sample.csv")))
    ab_rows = list(csv.DictReader(open(ROOT / "data/validation_sample_ab.csv")))
    desc = descriptions({r["vuln_id"] for r in ab_rows})
    for name, rows in (("c", c_rows), ("ab", ab_rows)):
        for i in range(0, len(rows), chunk):
            parts = []
            for r in rows[i:i + chunk]:
                sha = r["commit_url"].rsplit("/", 1)[1]
                head = f"## sample_id {r['sample_id']} | project {r['project']}"
                if name == "ab":
                    head += (f" | vuln {r['vuln_id']}\nVULNERABILITY DESCRIPTION:\n"
                             f"{desc.get(r['vuln_id'], '(no description available: ID of other software)')}\n")
                parts.append(head + "\n" + commit_text(r["project"], sha) + "\n")
            (out / f"{name}_{i // chunk + 1}.md").write_text("\n---\n".join(parts))
    print(sorted(p.name for p in out.glob("*.md")))


if __name__ == "__main__":
    main()
