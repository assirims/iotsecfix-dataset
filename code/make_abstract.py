"""Fill abstract_draft.txt from results/results.json (R2: no hand-typed numbers).

Mirrors the abstract in paper/main.tex. Usage: python code/make_abstract.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
r = json.loads((ROOT / "results/results.json").read_text())
t, cf = r["total"], r["external"]["cvefixes"]
text = (
    "Real-time operating systems, network stacks, firmware, and crypto libraries for "
    "Internet-of-Things (IoT) devices are developed in the open, but no vulnerability-fix dataset "
    "is, to our knowledge, organised around them. We present IoTSecFix, a dataset of "
    f"security-fixing commits in {r['selectedProjects']} open-source IoT projects, selected by "
    f"documented rules from a fixed pool of {r['poolSize']} GitHub repositories. IoTSecFix links "
    f"{t['vulns']:,} vulnerabilities (CVE or GitHub Security Advisory) to {t['fixCommits']:,} fix "
    "commits through three sources: commit messages that cite the identifier, NVD and advisory "
    "references to commits, and merged pull requests named in those references. Of the "
    f"{cf['preCutoffVulns']} vulnerabilities published before the data date of CVEfixes v1.0.8, "
    f"only {cf['preCutoffShared']} are in that dataset. Every link records its source and a change "
    "scope (code, test, or documentation/CI). Each record also gives the CWE, CVSS severity, fix "
    "and parent commits, files and lines changed, and the days between the fix and the "
    f"vulnerability's publication. Keyword-only candidate commits ({t['candidates']:,}) are "
    "released separately as unvalidated, with seeded samples for precision estimation. The "
    "release contains CSV and JSON files, JSON Schemas, a datasheet, and the collection scripts."
)
(ROOT / "abstract_draft.txt").write_text(text + "\n")
print(len(text.split()), "words")
