"""Download published repository security advisories (GHSA) for every candidate repo.

Uses `gh api` (already authenticated; the token never passes through this script) and
writes data/raw/ghsa/<id>.json = {"accessed_utc", "repo", "advisories": [...]}.

Usage: python code/ghsa_fetch.py
"""
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def fetch(repo: str) -> list:
    out = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", f"repos/{repo}/security-advisories?per_page=100"],
        capture_output=True, text=True, check=True).stdout
    return [a for page in json.loads(out) for a in page]


def main() -> None:
    out = ROOT / "data/raw/ghsa"
    out.mkdir(parents=True, exist_ok=True)
    for c in json.loads((ROOT / "code/projects.json").read_text())["candidates"]:
        advs = fetch(c["repo"])
        (out / f"{c['id']}.json").write_text(json.dumps(
            {"accessed_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "repo": c["repo"], "advisories": advs}))
        print(c["id"], len(advs), flush=True)


if __name__ == "__main__":
    main()
