"""Descriptive statistics of the release -> results/results.json and paper/generated/tab_*.tex.

Usage: python code/stats.py   (then: python ../shared/scripts/make_macros.py .)
"""
import csv
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import median, quantiles

ROOT = Path(__file__).resolve().parent.parent
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def q(xs: list[float]) -> dict:
    if not xs:
        return {"median": 0.0, "qOne": 0.0, "qThree": 0.0}
    if len(xs) == 1:
        return {"median": float(xs[0]), "qOne": float(xs[0]), "qThree": float(xs[0])}
    q1, _, q3 = quantiles(xs, n=4, method="inclusive")
    return {"median": float(median(xs)), "qOne": float(q1), "qThree": float(q3)}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def summarise(fixes: list[dict]) -> dict:
    vulns = {f["vuln_id"] for f in fixes}
    commits = {}
    for f in fixes:
        commits.setdefault(f["fix_commit"], f)
    tiers = {}
    for f in fixes:
        tiers.setdefault((f["vuln_id"], f["fix_commit"]), set()).update(f["tiers"].split(";"))
    first = {}
    for f in fixes:
        if f["fix_to_publication_days"] is not None:
            v = first.get(f["vuln_id"])
            if v is None or f["commit_date"] < v["commit_date"]:
                first[f["vuln_id"]] = f
    lag = [f["fix_to_publication_days"] for f in first.values()]
    return {
        "vulns": len(vulns), "records": len(fixes), "fixCommits": len(commits),
        "tierAOnly": sum(t == {"A"} for t in tiers.values()),
        "tierBOnly": sum(t == {"B"} for t in tiers.values()),
        "tierAB": sum(t == {"A", "B"} for t in tiers.values()),
        "files": q([c["files_changed"] for c in commits.values()]),
        "linesChanged": q([c["lines_added"] + c["lines_deleted"] for c in commits.values()]),
        "lagDays": q(lag), "lagN": len(lag),
        "scopeCode": sum(f.get("change_scope") == "code" for f in fixes),
        "scopeTest": sum(f.get("change_scope") == "test" for f in fixes),
        "scopeDocCi": sum(f.get("change_scope") == "doc_ci" for f in fixes),
        "tierAScopeDocCi": sum(f.get("change_scope") == "doc_ci" and f["tiers"] == "A" for f in fixes),
        "tierBScopeDocCi": sum(f.get("change_scope") == "doc_ci" and f["tiers"] != "A" for f in fixes),
        "fixBeforePublicationPct": round(100 * sum(x > 0 for x in lag) / len(lag), 1) if lag else 0.0,
    }


def tex_escape(s: str) -> str:
    return s.replace("_", r"\_").replace("&", r"\&").replace("%", r"\%")


def main() -> None:
    interim = json.loads((ROOT / "data/interim/projects.json").read_text())
    projects = interim["projects"]
    sel = [p for p in projects if p["selected"]]
    fixes = [f for p in sel for f in p["fixes"]]
    cands = [c for p in sel for c in p["candidates"]]

    per_vuln = {}
    for f in fixes:
        per_vuln.setdefault(f["vuln_id"], f)
    sev = Counter(v["severity"] or "NONE" for v in per_vuln.values())
    cwe = Counter(w for v in per_vuln.values() for w in v["cwe_ids"].split(";") if w)
    years = Counter(v["published"][:4] for v in per_vuln.values() if v["published"])
    linked = sum(p["linked_vulns"] for p in sel)
    linked_mapped = sum(p["linked_mapped"] for p in sel)

    res = {
        "_format": {"total.coveragePct": 1, "total.files.median": 0, "total.files.qOne": 0,
                    "total.files.qThree": 0, "total.linesChanged.median": 0,
                    "total.linesChanged.qOne": 0, "total.linesChanged.qThree": 0,
                    "total.lagDays.median": 0, "total.lagDays.qOne": 0, "total.lagDays.qThree": 0,
                    "total.fixBeforePublicationPct": 1, "total.withCwePct": 1, "total.zephyrSharePct": 1, "extra.coreCommitsWithCPct": 1, "extra.near60ZephyrPct": 1, "cpe.pct": 1, "extra.lagNoZephyrMedian": 0},
        "snapshotDate": "2026-10-25",
        "nvdCves": interim["nvd_cves"],
        "keywordClasses": len(__import__("linking").KEYWORDS),
        "poolSize": len(projects), "selectedProjects": len(sel),
        "excludedInactive": sum(p["exclusion"].startswith("I1") for p in projects),
        "excludedFewVulns": sum(p["exclusion"].startswith("I2") for p in projects),
        "excludedRank": sum(p["exclusion"].startswith("I3") for p in projects),
        "commitsScanned": sum(p["n_commits"] for p in sel),
        "total": {**summarise(fixes),
                  "linkedVulns": linked, "linkedMapped": linked_mapped,
                  "coveragePct": round(100 * linked_mapped / linked, 1) if linked else 0.0,
                  "citedNotLinked": len({f["vuln_id"] for f in fixes if not f["id_linked_to_project"]}),
                  "ghsaOnly": sum(1 for v in per_vuln.values() if not v["cve_id"]),
                  "distinctCwes": len(cwe),
                  "withCwePct": round(100 * sum(1 for v in per_vuln.values() if v["cwe_ids"])
                                      / len(per_vuln), 1) if per_vuln else 0.0,
                  "prUnresolved": sum(p["pr_unresolved_vulns"] for p in sel),
                  "candidates": len(cands),
                  "core": {k: v for k, v in summarise(
                      [f for f in fixes if f["change_scope"] == "code"]).items()
                      if k in ("vulns", "records", "fixCommits")},
                  "largePrRecords": sum((f["pr_commits"] or 0) > 5 for f in fixes),
                  "largePrVulns": len({f["vuln_id"] for f in fixes if (f["pr_commits"] or 0) > 5}),
                  "reverts": sum(f["is_revert"] for f in fixes),
                  "offDefaultBranch": sum(not f["on_default_branch"] for f in fixes),
                  "latestYearVulns": years[max(years)] if years else 0,
                  "zephyrSharePct": round(100 * sum(v["project"] == "zephyr" for v in per_vuln.values())
                                          / len(per_vuln), 1) if per_vuln else 0.0,
                  "earliestYear": min(years) if years else "", "latestYear": max(years) if years else ""},
        "severity": {s.lower(): sev.get(s, 0) for s in SEVS + ["NONE"]},
        "project": {p["id"]: {"vulns": len({f["vuln_id"] for f in p["fixes"]}),
                              "candidates": len(p["candidates"])} for p in sel},
    }
    # --- additions after review round 1 (definitions in PROTOCOL.md section 6) ---
    pairs = {(f["project"], f["vuln_id"]) for f in fixes}
    commits = {}
    for f in fixes:
        commits.setdefault(f["fix_commit"], f)
    core = [f for f in fixes if f["change_scope"] == "code"]
    core_commits = {f["fix_commit"]: f for f in core}
    per_vuln_commits = Counter()
    for v, h in {(f["vuln_id"], f["fix_commit"]) for f in core}:
        per_vuln_commits[v] += 1
    lagv = [f["fix_to_publication_days"] for f in per_vuln.values()]
    first = {}
    for f in fixes:
        if f["fix_to_publication_days"] is not None:
            o = first.get(f["vuln_id"])
            if o is None or f["commit_date"] < o["commit_date"]:
                first[f["vuln_id"]] = f
    near60 = [f for f in first.values() if 55 <= f["fix_to_publication_days"] <= 65]
    latest = [v for v in per_vuln.values() if v["published"][:4] == res["total"]["latestYear"]]
    nvd_first = json.loads(sorted((ROOT / "data/raw/nvd").glob("page_*.json"))[0].read_text())
    sel_ids = {p["id"] for p in sel}
    res["extra"] = {
        "projectVulnPairs": len(pairs),
        "multiProjectVulns": sum(c > 1 for c in Counter(v for _, v in pairs).values()),
        "foreignGhsaVulns": sum(1 for v in per_vuln.values() if v["vuln_id"].startswith("GHSA")
                                and not v["id_linked_to_project"]),
        "citedOnlyPairs": len(pairs) - res["total"]["linkedMapped"],
        "noDateVulns": sum(1 for v in per_vuln.values() if not v["published"]),
        "notInNvdNoGhsa": sum(1 for v in per_vuln.values() if not v["in_nvd"] and not v["ghsa_id"]),
        "mergeFixCommits": sum(";" in c["parent_commits"] for c in commits.values()),
        "coreCommitsWithC": sum(c["c_cpp_files"] > 0 for c in core_commits.values()),
        "coreCommitsWithCPct": round(100 * sum(c["c_cpp_files"] > 0 for c in core_commits.values())
                                     / len(core_commits), 1) if core_commits else 0.0,
        "coreSingleCommitVulns": sum(n == 1 for n in per_vuln_commits.values()),
        "unresolvedRefShas": sum(p["unresolved_ref_shas"] for p in sel),
        "near60Vulns": len(near60),
        "near60ZephyrPct": round(100 * sum(f["project"] == "zephyr" for f in near60) / len(near60), 1)
        if near60 else 0.0,
        "latestYearZephyrGhsa": sum(v["project"] == "zephyr" and bool(v["ghsa_id"]) for v in latest),
        "nvdTotalAtStart": nvd_first["totalResults"],
        "excludedNames": ", ".join(sorted(p["repo"].split("/")[1] for p in projects if not p["selected"])),
    }
    ch = Counter()
    for p in sel:
        ch.update(p["linked_channels"])
    res["extra"].update({"linkedNvdOnly": ch.get("nvd", 0), "linkedGhsaOnly": ch.get("ghsa", 0),
                         "linkedBoth": ch.get("nvdghsa", 0),
                         "projectsWithGhsa": sum(any("ghsa" in k for k in p["linked_channels"])
                                                 for p in sel)})
    nz = [f["fix_to_publication_days"] for f in first.values() if f["project"] != "zephyr"]
    res["extra"]["lagNoZephyrMedian"] = float(median(nz)) if nz else 0.0
    res["extra"]["lagNoZephyrN"] = len(nz)
    fc = [p["first_commit"] for p in sel if p["id"] in ("threadx", "netxduo")]
    res["extra"]["threadxFirstYear"] = (str(datetime.fromtimestamp(min(fc), tz=timezone.utc).year)
                                        if fc else 0)
    # single-commit fixes: core records on the default branch, merge commits excluded
    strict = Counter(v for v, _ in {(f["vuln_id"], f["fix_commit"]) for f in core
                                    if f["on_default_branch"] and ";" not in f["parent_commits"]})
    res["extra"]["coreSingleCommitVulns"] = sum(n == 1 for n in strict.values())
    cov_f = ROOT / "data/interim/coverage.json"
    if cov_f.exists():
        cov = json.loads(cov_f.read_text())["projects"]
        cov = {k: v for k, v in cov.items() if k in sel_ids}
        n = sum(v["cpe_cves"] for v in cov.values())
        m = sum(v["cpe_mapped"] for v in cov.values())
        res["cpe"] = {"cves": n, "mapped": m, "pct": round(100 * m / n, 1) if n else 0.0,
                      "beforeTwentySeventeen": sum(v["cpe_before_2017"] for v in cov.values()),
                      "mbedtlsCves": cov.get("mbedtls", {}).get("cpe_cves", 0),
                      "mbedtlsMapped": cov.get("mbedtls", {}).get("cpe_mapped", 0)}
        rt = cov.get("mbedtls", {}).get("nvd_github_ref_types", {})
        res["cpe"]["mbedtlsRefs"] = sum(rt.values())
        res["cpe"]["mbedtlsReleaseRefs"] = rt.get("releases", 0)
        res["cpe"]["mbedtlsCommitRefs"] = rt.get("commit", 0)
    ext_f = ROOT / "data/interim/external_overlap.json"
    if ext_f.exists():
        res["external"] = {k: {kk: vv for kk, vv in v.items() if kk != "source"}
                           for k, v in json.loads(ext_f.read_text()).items()}
    val = ROOT / "data/validation_sample.csv"
    if val.exists():
        rows = list(csv.DictReader(open(val)))
        lab = [r for r in rows if r["label"].strip()]
        res["validation"] = {"sampleSize": len(rows), "labelled": len(lab)}
        if lab and len(lab) == len(rows):
            k = sum(r["label"].strip() == "security_fix" for r in lab)
            lo, hi = wilson(k, len(lab))
            res["validation"].update({"securityFix": k, "precisionPct": round(100 * k / len(lab), 1),
                                      "ciLowPct": round(100 * lo, 1), "ciHighPct": round(100 * hi, 1)})
    vab = ROOT / "data/validation_sample_ab.csv"
    if vab.exists():
        rows = list(csv.DictReader(open(vab)))
        res["validationAb"] = {"sampleSize": len(rows),
                               "labelled": sum(bool(r["label"].strip()) for r in rows)}
        if rows and all(r["label"].strip() for r in rows):
            for tier in ("A", "B"):
                rs = [r for r in rows if r["stratum"] == tier]
                k = sum(r["label"].strip() in ("fixes_vulnerability", "part_of_fix") for r in rs)
                lo, hi = wilson(k, len(rs))
                res["validationAb"][f"tier{tier}"] = {
                    "n": len(rs), "correct": k, "precisionPct": round(100 * k / len(rs), 1),
                    "ciLowPct": round(100 * lo, 1), "ciHighPct": round(100 * hi, 1)}
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results/results.json").write_text(json.dumps(res, indent=2))

    gen = ROOT / "paper/generated"
    gen.mkdir(parents=True, exist_ok=True)
    covp = json.loads(cov_f.read_text())["projects"] if cov_f.exists() else {}

    def cpe_cell(pid: str) -> str:
        c = covp.get(pid)
        return f"{c['cpe_mapped']}/{c['cpe_cves']}" if c else "--"

    lines = [r"% GENERATED by code/stats.py. Do not edit.",
             r"\begin{tabular}{@{}llrrrrrrr@{}}", r"\toprule",
             r"Project & Kind & Commits & Linked & \shortstack{Linked\\mapped} & Mapped & "
             r"\shortstack{CPE\\mapped} & \shortstack{Fix\\commits} & Tier C \\", r"\midrule"]
    for p in sorted(sel, key=lambda p: -p["mapped_vulns"]):
        s = summarise(p["fixes"])
        lines.append(f"{tex_escape(p['repo'].split('/')[1])} & {p['kind']} & {p['n_commits']:,} & "
                     f"{p['linked_vulns']} & {p['linked_mapped']} & {s['vulns']} & {cpe_cell(p['id'])} & "
                     f"{s['fixCommits']:,} & {len(p['candidates']):,} \\\\".replace(",", "{,}"))
    t = res["total"]
    cp = res.get("cpe", {})
    lines += [r"\midrule",
              f"Total & & {res['commitsScanned']:,} & {t['linkedVulns']} & {t['linkedMapped']} & "
              f"{t['vulns']} & {cp.get('mapped', 0)}/{cp.get('cves', 0)} & "
              f"{t['fixCommits']:,} & {t['candidates']:,} \\\\".replace(",", "{,}"),
              r"\bottomrule", r"\end{tabular}"]
    (gen / "tab_projects.tex").write_text("\n".join(lines) + "\n")
    lines = [r"% GENERATED by code/stats.py. Do not edit.", r"\begin{tabular}{@{}lr@{}}", r"\toprule",
             r"CWE & Vulns \\", r"\midrule"]
    lines += [f"{w} & {n} \\\\" for w, n in cwe.most_common(10)]
    lines += [r"\bottomrule", r"\end{tabular}"]
    (gen / "tab_cwe.tex").write_text("\n".join(lines) + "\n")
    lines = [r"% GENERATED by code/stats.py. Do not edit.", r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
             r"Link tiers & code & test & doc/CI & All \\", r"\midrule"]
    for name, tv in (("A only", "A"), ("B only", "B"), ("A and B", "A;B")):
        rows = [f for f in fixes if f["tiers"] == tv]
        c = Counter(f["change_scope"] for f in rows)
        lines.append(f"{name} & {c['code']:,} & {c['test']:,} & {c['doc_ci']:,} & {len(rows):,} \\\\"
                     .replace(",", "{,}"))
    c = Counter(f["change_scope"] for f in fixes)
    lines += [r"\midrule", f"All & {c['code']:,} & {c['test']:,} & {c['doc_ci']:,} & {len(fixes):,} \\\\"
              .replace(",", "{,}"), r"\bottomrule", r"\end{tabular}"]
    (gen / "tab_quality.tex").write_text("\n".join(lines) + "\n")
    # generated sentences (so the paper text changes only through scripts)
    va, vc = res.get("validationAb", {}), res.get("validation", {})
    if "tierA" in va:
        a_, b_ = va["tierA"], va["tierB"]
        sab = (f"On a seeded sample of {va['sampleSize']} records labelled by the author, link precision "
               f"is {a_['precisionPct']}\\% for tier~A (95\\% CI {a_['ciLowPct']}--{a_['ciHighPct']}) and "
               f"{b_['precisionPct']}\\% for tier~B ({b_['ciLowPct']}--{b_['ciHighPct']}).")
    else:
        sab = (f"A seeded sample of {va.get('sampleSize', 0)} records (half tier~A, half tier~B) is being "
               "labelled by the author to estimate link precision per tier.")
    if "precisionPct" in vc:
        sc = (f"Of {vc['labelled']} seeded tier-C candidates labelled by the author, {vc['securityFix']} are "
              f"security fixes (precision {vc['precisionPct']}\\%, 95\\% CI {vc['ciLowPct']}--{vc['ciHighPct']}).")
    else:
        sc = (f"Tier~C precision is not yet known: a seeded, project-stratified sample of "
              f"{vc.get('sampleSize', 0)} candidates is being labelled by the author.")
    (gen / "validation.tex").write_text("% GENERATED by code/stats.py.\n" + sab + "\n" + sc + "\n")
    ext = res.get("external", {})
    parts = []
    names = {"projectKb": "Project~KB~\\cite{ponta2019projectkb}", "cvefixes": "CVEfixes v1.0.8~\\cite{bhandari2021cvefixes}"}
    for k, e in ext.items():
        t_ = (f"{names[k]} shares {e['sharedVulns']} of our {res['total']['vulns']} vulnerability IDs and "
              f"{e['sharedCommits']} of our {res['total']['fixCommits']:,} fix commits".replace(",", "{,}"))
        if "preCutoffVulns" in e:
            t_ += (f" (of our {e['preCutoffVulns']} vulnerabilities published before its 2024-07-23 NVD feed, "
                   f"{e['preCutoffShared']} are in it)")
        parts.append(t_)
    so = ("We compared \\ds with existing releases by vulnerability ID and commit SHA. " + "; ".join(parts) + "."
          if parts else "")
    (gen / "overlap.tex").write_text("% GENERATED by code/stats.py.\n" + so + "\n")
    v = res.get("validation")
    if v and "precisionPct" in v:
        vs = (f"{v['labelled']} seeded random tier-C candidates labelled by a project author: "
              f"{v['securityFix']} security fixes, precision {v['precisionPct']}% "
              f"(Wilson 95% CI {v['ciLowPct']}-{v['ciHighPct']}%).")
    elif v:
        vs = f"Sample of {v['sampleSize']} tier-C candidates drawn; labelling pending ({v['labelled']} done)."
    else:
        vs = "Validation sample not yet drawn."
    vs = (sab + " " + sc).replace("~", " ").replace("\\%", "%")
    tmpl = (ROOT / "code/DATASHEET.template.md").read_text().replace("VALIDATION_SECTION", vs)
    (ROOT / "data/release/DATASHEET.md").write_text(tmpl.format(**res))
    print(json.dumps(res["total"], indent=1))


if __name__ == "__main__":
    main()
