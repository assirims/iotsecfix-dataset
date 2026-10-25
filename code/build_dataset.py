"""Build IoTSecFix from the cached NVD pages, GHSA files and blobless clones.

Inputs (from nvd_fetch.py, ghsa_fetch.py, clone.sh): data/raw/{nvd,ghsa,repos}.
Outputs: data/interim/projects.json (every candidate, before selection),
         data/release/iotsecfix_fixes.{csv,json}, data/release/iotsecfix_candidates.{csv,json}.
Usage: python code/build_dataset.py
"""
import csv
import json
import re
import subprocess
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import linking as L

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data/raw"
ACTIVE_SINCE = "2025-10-25"
MIN_MAPPED, MAX_PROJECTS = 5, 15
SCOPE_V = 2  # bump when linking.change_scope changes, to recompute cached scopes
C_EXT = re.compile(r"\.(?:c|h|cc|cpp|cxx|hh|hpp|hxx|ino)$", re.I)

FIX_FIELDS = ["project", "repo", "vuln_id", "cve_id", "ghsa_id", "cwe_ids", "cvss_version",
              "cvss_score", "severity", "severity_source", "published", "fix_commit",
              "parent_commits", "commit_date", "on_default_branch", "is_revert",
              "pr_commits", "change_scope", "files_changed", "c_cpp_files", "lines_added", "lines_deleted", "fix_to_publication_days",
              "tiers", "link_sources", "id_linked_to_project", "in_nvd", "nvd_url",
              "commit_url"]
CAND_FIELDS = ["project", "repo", "commit", "parent_commits", "commit_date", "keywords",
               "subject", "commit_url"]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True, errors="replace").stdout


def load_nvd() -> dict:
    """CVE id -> minimal record. Keeps only GitHub reference URLs."""
    idx = {}
    for f in sorted((RAW / "nvd").glob("page_*.json")):
        for v in json.loads(f.read_text())["vulnerabilities"]:
            c = v["cve"]
            ver, score, sev = L.nvd_severity(c)
            idx[c["id"]] = {
                "published": c["published"], "status": c.get("vulnStatus", ""),
                "cvss_version": ver, "cvss_score": score, "severity": sev,
                "cwes": L.nvd_cwes(c),
                "refs": [r["url"] for r in c.get("references", []) if "github.com" in r["url"].lower()]}
    return idx


def git_commits(repo: Path) -> dict:
    out = git(repo, "log", "--all", "--format=%H%x1f%P%x1f%ct%x1f%B%x1e")
    commits = {}
    for rec in out.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        h, parents, ct, body = rec.split("\x1f", 3)
        commits[h] = {"parents": parents.split(), "ct": int(ct), "msg": body.strip()}
    return commits


def resolve(sha: str, commits: dict, by_prefix: dict, repo: Path) -> str | None:
    if sha in commits:
        return sha
    if len(sha) < 40:
        hits = by_prefix.get(sha[:7], [])
        hits = [h for h in hits if h.startswith(sha)]
        return hits[0] if len(hits) == 1 else None
    # full SHA not on any fetched ref (e.g. PR branch): GitHub serves it on request
    r = subprocess.run(["git", "-C", str(repo), "fetch", "-q", "--filter=blob:none", "origin", sha],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    meta = git(repo, "log", "-1", "--format=%P%x1f%ct%x1f%B", sha).split("\x1f", 2)
    commits[sha] = {"parents": meta[0].split(), "ct": int(meta[1]), "msg": meta[2].strip()}
    return sha


def pr_fix_commits(repo: str, number: int, prs: dict, commits: dict, by_prefix: dict,
                   clone: Path) -> list[str]:
    """Commits that a merged PR put on the target branch (cached in data/raw/prs.json).

    True merge (2 parents): the merge commit (diff vs first parent = whole PR).
    Squash or rebase (1 parent): walk the first-parent chain back from merge_commit_sha for
    as many commits as the PR had and keep those whose subject matches a PR commit subject;
    the merge_commit_sha itself is always kept (squash: its subject is the PR title).
    """
    k = f"{repo}#{number}"
    if k not in prs:
        r = subprocess.run(["gh", "api", f"repos/{repo}/pulls/{number}", "--jq",
                            "{merged, merge_commit_sha}"], capture_output=True, text=True)
        prs[k] = json.loads(r.stdout) if r.returncode == 0 else {"merged": False}
    pr = prs[k]
    if not pr.get("merged"):
        return []
    head = resolve(pr["merge_commit_sha"], commits, by_prefix, clone)
    if head is None:
        return []
    if len(commits[head]["parents"]) > 1:
        return [head]
    if "subjects" not in pr:
        r = subprocess.run(["gh", "api", f"repos/{repo}/pulls/{number}/commits?per_page=250",
                            "--jq", "[.[].commit.message | split(\"\\n\")[0]]"],
                           capture_output=True, text=True)
        pr["subjects"] = json.loads(r.stdout) if r.returncode == 0 else []
    subjects = set(pr["subjects"])
    out, h = [head], head
    for _ in range(max(len(pr["subjects"]) - 1, 0)):
        ps = commits[h]["parents"]
        if len(ps) != 1 or ps[0] not in commits:
            break
        h = ps[0]
        if (commits[h]["msg"].splitlines() or [""])[0] in subjects:
            out.append(h)
        else:
            break
    return out


def numstat(repo: Path, sha: str, parents: list[str]) -> dict:
    args = ["diff", "--numstat", "--no-renames", parents[0], sha] if parents else \
           ["show", "--numstat", "--no-renames", "--format=", sha]
    add = dele = 0
    paths = []
    for line in git(repo, *args).splitlines():
        a, d, path = line.split("\t", 2)
        paths.append(path)
        add += int(a) if a != "-" else 0
        dele += int(d) if d != "-" else 0
    return {"files": len(paths), "add": add, "del": dele, "scope": L.change_scope(paths),
            "cfiles": sum(bool(C_EXT.search(p)) for p in paths), "v": SCOPE_V}


def build_project(c: dict, nvd: dict, cache: dict, prs: dict) -> dict:
    repo = RAW / "repos" / c["id"]
    names = [c["repo"], *c["aliases"]]
    rpat = L.repo_pattern(names)
    commits = git_commits(repo)
    default = set(git(repo, "rev-list", "origin/HEAD").split())
    by_prefix = defaultdict(list)
    for h in commits:
        by_prefix[h[:7]].append(h)

    # linked vulnerabilities: key = CVE id if any, else GHSA id
    vulns = {}
    ghsa2cve = {}
    for cid, r in nvd.items():
        if r["status"] != "Rejected" and any(rpat.search(u) for u in r["refs"]):
            vulns[cid] = {"cve": cid, "ghsa": "", "text": "\n".join(r["refs"]), "ghsa_rec": None}
    advs = json.loads((RAW / "ghsa" / f"{c['id']}.json").read_text())["advisories"]
    for a in advs:
        if a.get("withdrawn_at"):
            continue
        key = a.get("cve_id") or a["ghsa_id"]
        ghsa2cve[a["ghsa_id"].lower()] = key
        v = vulns.setdefault(key, {"cve": a.get("cve_id") or "", "ghsa": "", "text": "", "ghsa_rec": None})
        v["ghsa"], v["ghsa_rec"] = a["ghsa_id"], a
        v["text"] += "\n" + (a.get("summary") or "") + "\n" + (a.get("description") or "")
    linked = set(vulns)
    channels = Counter(("nvd" if any(rpat.search(u) for u in nvd.get(v["cve"], {}).get("refs", []))
                        else "") + ("ghsa" if v["ghsa_rec"] else "") for v in vulns.values())

    links = defaultdict(lambda: {"tiers": set(), "sources": set()})  # (key, sha) -> info
    missing_refs = 0
    pr_only = 0
    for key, v in vulns.items():
        shas = L.commit_urls(v["text"], names)
        nvd_shas = L.commit_urls("\n".join(nvd.get(v["cve"], {}).get("refs", [])), names)
        found = False
        for s in shas:
            full = resolve(s, commits, by_prefix, repo)
            if full is None:
                missing_refs += 1
                continue
            found = True
            info = links[(key, full)]
            info["tiers"].add("B")
            info["sources"].add("nvd_ref" if s in nvd_shas else "ghsa_text")
        nvd_prs = L.pr_urls("\n".join(nvd.get(v["cve"], {}).get("refs", [])), names)
        for n in sorted(L.pr_urls(v["text"], names)):
            pr_shas = pr_fix_commits(c["repo"], n, prs, commits, by_prefix, repo)
            for full in pr_shas:
                found = True
                info = links[(key, full)]
                info["pr_commits"] = max(info.get("pr_commits", 0), len(pr_shas))
                info["tiers"].add("B")
                info["sources"].add("nvd_pr" if n in nvd_prs else "ghsa_pr")
        if not found and L.pr_urls(v["text"], names):
            pr_only += 1

    for h, m in commits.items():
        cves, ghsas = L.find_ids(m["msg"])
        keys = cves | {ghsa2cve.get(g.lower(), g) for g in ghsas}
        for key in keys:
            if key.startswith("CVE-") and nvd.get(key, {}).get("status") == "Rejected":
                continue
            info = links[(key, h)]
            info["tiers"].add("A")
            info["sources"].add("commit_message")

    fixes = []
    work = sorted({h for (_, h) in links if cache.get(f"{c['id']}:{h}", {}).get("v") != SCOPE_V or "cfiles" not in cache.get(f"{c['id']}:{h}", {})})
    with ThreadPoolExecutor(8) as ex:
        for h, ns in zip(work, ex.map(lambda h: numstat(repo, h, commits[h]["parents"]), work)):
            cache[f"{c['id']}:{h}"] = ns
    for (key, h), info in sorted(links.items()):
        m, ns = commits[h], cache[f"{c['id']}:{h}"]
        v = vulns.get(key, {})
        cve = key if key.startswith("CVE-") else v.get("cve", "")
        n = nvd.get(cve) if cve else None
        g = v.get("ghsa_rec")
        if g is None and key.startswith("GHSA"):
            g = None  # GHSA cited in a message but not published in this repo
        cwes = list(n["cwes"]) if n else []
        for w in (g or {}).get("cwe_ids") or []:
            if w not in cwes:
                cwes.append(w)
        if n and n["severity"]:
            ver, score, sev, src = n["cvss_version"], n["cvss_score"], n["severity"], "nvd"
        elif g:
            (ver, score, sev), src = L.ghsa_severity(g), "ghsa"
        else:
            ver, score, sev, src = "", None, "", ""
        pubs = [p for p in ((n or {}).get("published"), (g or {}).get("published_at")) if p]
        pub = min(pubs, key=lambda p: L.parse_ts(p)) if pubs else ""
        fixes.append({
            "project": c["id"], "repo": c["repo"], "vuln_id": key, "cve_id": cve,
            "ghsa_id": (g or {}).get("ghsa_id", key if key.startswith("GHSA") else ""),
            "cwe_ids": ";".join(cwes), "cvss_version": ver, "cvss_score": score,
            "severity": sev, "severity_source": src, "published": pub, "fix_commit": h,
            "parent_commits": ";".join(m["parents"]),
            "commit_date": L.datetime.fromtimestamp(m["ct"], tz=L.timezone.utc).isoformat(),
            "on_default_branch": h in default, "is_revert": L.is_revert(m["msg"]),
            "pr_commits": info.get("pr_commits"), "change_scope": ns["scope"], "files_changed": ns["files"], "c_cpp_files": ns["cfiles"], "lines_added": ns["add"], "lines_deleted": ns["del"],
            "fix_to_publication_days": L.days_between(pub, m["ct"]) if pub else None,
            "tiers": ";".join(sorted(info["tiers"])), "link_sources": ";".join(sorted(info["sources"])),
            "id_linked_to_project": key in linked, "in_nvd": bool(n),
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}" if n else "",
            "commit_url": f"https://github.com/{c['repo']}/commit/{h}"})

    ab = {f["fix_commit"] for f in fixes}
    cands = []
    for h, m in commits.items():
        if h in default and h not in ab:
            kws = L.keyword_hits(m["msg"])
            if kws:
                cands.append({
                    "project": c["id"], "repo": c["repo"], "commit": h,
                    "parent_commits": ";".join(m["parents"]),
                    "commit_date": L.datetime.fromtimestamp(m["ct"], tz=L.timezone.utc).isoformat(),
                    "keywords": ";".join(kws), "subject": m["msg"].splitlines()[0][:200],
                    "commit_url": f"https://github.com/{c['repo']}/commit/{h}"})
    cands.sort(key=lambda r: r["commit_date"])
    return {"id": c["id"], "repo": c["repo"], "kind": c["kind"], "n_commits": len(commits),
            "n_default_commits": len(default), "linked_vulns": len(linked),
            "linked_mapped": len({k for k, _ in links if k in linked}),
            "mapped_vulns": len({k for k, _ in links}),
            "unresolved_ref_shas": missing_refs, "linked_channels": dict(channels),
            "first_commit": min((m["ct"] for h, m in commits.items() if h in default), default=0), "pr_unresolved_vulns": pr_only, "head": git(repo, "rev-parse", "origin/HEAD").strip(),
            "fixes": fixes, "candidates": cands}


def write(rows: list[dict], fields: list[str], stem: Path) -> None:
    with open(stem.with_suffix(".csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    stem.with_suffix(".json").write_text(json.dumps(rows, indent=1))


def main() -> None:
    cfg = json.loads((ROOT / "code/projects.json").read_text())["candidates"]
    nvd = load_nvd()
    meta = {c["id"]: json.loads(subprocess.run(
        ["gh", "api", f"repos/{c['repo']}", "--jq", "{archived,fork,pushed_at}"],
        capture_output=True, text=True, check=True).stdout) for c in cfg}
    cache_f = RAW / "numstat_cache.json"
    cache = json.loads(cache_f.read_text()) if cache_f.exists() else {}
    prs_f = RAW / "prs.json"
    prs = json.loads(prs_f.read_text()) if prs_f.exists() else {}
    projects = []
    for c in cfg:
        p = build_project(c, nvd, cache, prs)
        cache_f.write_text(json.dumps(cache))
        prs_f.write_text(json.dumps(prs))
        p.update(meta[c["id"]])
        p["active"] = not p["archived"] and not p["fork"] and p["pushed_at"][:10] >= ACTIVE_SINCE
        print(c["id"], p["linked_vulns"], p["mapped_vulns"], len(p["fixes"]), len(p["candidates"]),
              flush=True)
        projects.append(p)
    ok = sorted([p for p in projects if p["active"] and p["mapped_vulns"] >= MIN_MAPPED],
                key=lambda p: -p["mapped_vulns"])
    selected = {p["id"] for p in ok[:MAX_PROJECTS]}
    for p in projects:
        p["selected"] = p["id"] in selected
        p["exclusion"] = ("" if p["selected"] else "I1 inactive" if not p["active"] else
                          f"I2 mapped<{MIN_MAPPED}" if p["mapped_vulns"] < MIN_MAPPED else "I3 rank>15")
    (ROOT / "data/interim").mkdir(parents=True, exist_ok=True)
    (ROOT / "data/interim/projects.json").write_text(json.dumps(
        {"nvd_cves": len(nvd), "projects": projects}, indent=1))
    rel = ROOT / "data/release"
    rel.mkdir(parents=True, exist_ok=True)
    sel = [p for p in projects if p["selected"]]
    write([f for p in sel for f in p["fixes"]], FIX_FIELDS, rel / "iotsecfix_fixes")
    write([r for p in sel for r in p["candidates"]], CAND_FIELDS, rel / "iotsecfix_candidates")
    print("selected:", sorted(selected))


if __name__ == "__main__":
    main()
