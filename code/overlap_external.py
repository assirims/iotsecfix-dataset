"""Overlap of IoTSecFix with existing fix datasets -> data/interim/external_overlap.json.

Sources (official releases, see PROTOCOL.md section 3):
- Project KB, branch vulnerability-data of github.com/SAP/project-kb (statements/*/statement.yaml)
- CVEfixes v1.0.8 (Zenodo record 13118970): rows of table `fixes` streamed out of the SQL dump
  with `unzip -p CVEfixes_v1.0.8.zip CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz | gunzip -c |
  grep "^INSERT INTO fixes VALUES" > data/raw/external/cvefixes_fixes.sql`
Matches: same vulnerability ID; same commit (full SHA, or SHA prefix match of >= 7 chars).
Usage: python code/overlap_external.py
"""
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
EXT = ROOT / "data/raw/external"


def compare(name: str, ids: set[str], shas: set[str], fixes: list[dict], cutoff: str = "") -> dict:
    """cutoff: the source's data date; also report overlap among our vulns published before it."""
    vulns = {f["vuln_id"] for f in fixes}
    ours = {f["fix_commit"] for f in fixes}
    hit = {h for h in ours if h in shas or any(s and h.startswith(s) for s in shas if len(s) < 40)}
    core = [f for f in fixes if f["change_scope"] == "code"]
    return {"source": name, "theirVulns": len(ids), "theirCommits": len(shas),
            "sharedVulns": len(vulns & ids), "sharedCommits": len(hit),
            "newVulns": len(vulns - ids), "newCommits": len(ours - hit),
            "coreNewVulns": len({f["vuln_id"] for f in core} - ids),
            **({"preCutoffVulns": len(pre := {f["vuln_id"] for f in fixes
                                              if f["published"] and f["published"][:10] < cutoff}),
                "preCutoffShared": len(pre & ids)} if cutoff else {})}


def project_kb() -> tuple[set, set]:
    ids, shas = set(), set()
    for f in (EXT / "project-kb/statements").glob("*/statement.yaml"):
        st = yaml.safe_load(f.read_text()) or {}
        ids.add(st.get("vulnerability_id", ""))
        for fx in st.get("fixes") or []:
            for c in fx.get("commits") or []:
                shas.add(str(c.get("id", "")).lower())
    return ids - {""}, shas - {""}


def cvefixes(dump: Path) -> tuple[set, set]:
    rows = re.findall(r"^INSERT INTO fixes VALUES\('([^']*)','([^']*)',", dump.read_text(), re.M)
    return {r[0] for r in rows}, {r[1].lower() for r in rows if r[1]}


def main() -> None:
    fixes = json.loads((ROOT / "data/release/iotsecfix_fixes.json").read_text())
    out = {}
    if (EXT / "project-kb/statements").exists():
        out["projectKb"] = compare("Project KB (vulnerability-data)", *project_kb(), fixes)
    if (EXT / "cvefixes_fixes.sql").exists():
        out["cvefixes"] = compare("CVEfixes v1.0.8", *cvefixes(EXT / "cvefixes_fixes.sql"), fixes,
                                  cutoff="2024-07-23")  # NVD feed date inside the release
    (ROOT / "data/interim/external_overlap.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
