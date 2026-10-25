# P5 PROTOCOL — IoTSecFix: a curated dataset of security-fixing commits in open-source IoT software

Venue: MSR 2027 Data and Tool Showcase (4 + 1 pages, single-anonymous; see CFP.md).
Snapshot date: 2026-10-25 (all sources accessed that day; exact UTC times in
`data/raw/nvd/_meta.json`, `data/raw/ghsa/*.json` and `data/raw/clone.log`).
Data showcase track: no empirical RQs. The paper describes the dataset, how it was built,
how good the links are, and what it can be used for.

## 1. Summary (10 lines)
1. Fixed pool of 19 IoT OS / firmware / protocol-stack / crypto repos on GitHub (section 2).
2. Sources: full NVD CVE catalogue (API 2.0), GitHub repository advisories (GHSA), git history.
3. Tier A: commits whose message cites a CVE or GHSA ID.
4. Tier B: NVD reference URLs or GHSA texts that point to a commit of the project.
5. Tier C: keyword-only candidates (security words, no ID, no link). Unvalidated.
6. Each A/B record: vuln ID, CWE, CVSS severity, fix commit, parent(s), files, lines +/-,
   days between fix commit and public disclosure.
7. Projects kept if >= 5 vulnerabilities map to >= 1 fix commit (max 15).
8. Release: CSV + JSON + JSON Schema + datasheet; all scripts; descriptive statistics.
9. A seeded random sample of tier C is labelled by the user (R10c) to estimate precision.
10. No overlap with P3: P3 mines DL-IDS research repos; P5 mines IoT OS/firmware repos.

## 2. Project selection (reproducible)
Candidate pool fixed before any vulnerability counting (`code/projects.json`, 19 repos):
software that runs on, or is a protocol/crypto/network stack built for, constrained or
embedded IoT devices; canonical repo on GitHub; written mainly in C/C++/Python.
Pool: Zephyr, RIOT, Contiki-NG, Apache NuttX, FreeRTOS-Kernel, FreeRTOS-Plus-TCP,
Eclipse ThreadX, NetX Duo, ESP-IDF, MicroPython, ESPHome, Tasmota, OpenThread,
Eclipse Mosquitto, open62541, Mbed TLS, wolfSSL, Mongoose, Mbed OS.

Inclusion (applied by `code/build_dataset.py`, outcome logged in results.json):
- I1 not archived, not a fork, last push on or after 2025-10-25 (active in the last year);
- I2 at least 5 distinct vulnerabilities (CVE or GHSA) mapped to >= 1 fix commit (tier A or B)
  that exists in the clone;
- I3 if more than 15 pass, keep the 15 with the most mapped vulnerabilities.
Former repo names (renames/transfers) are listed as `aliases` so old NVD URLs still match.

## 3. Sources
| Source | Access | Notes |
|---|---|---|
| NVD CVE API 2.0 `services.nvd.nist.gov/rest/json/cves/2.0` | 2026-10-25, keyless (5 req/30 s, sleep 6.5 s), full catalogue, 2,000/page | `code/nvd_fetch.py`, cached in `data/raw/nvd/` |
| GitHub repository security advisories `GET /repos/{repo}/security-advisories` | 2026-10-25 via `gh api` (token stays inside gh) | `code/ghsa_fetch.py`, `data/raw/ghsa/` |
| Project KB, branch `vulnerability-data` of github.com/SAP/project-kb | 2026-10-25, shallow clone, commit 730d2192 (2024-12-11) | overlap check only (`code/overlap_external.py`) |
| CVEfixes v1.0.8, Zenodo record 13118970, `CVEfixes_v1.0.8.zip` (12.7 GB, md5 4586a358977acfa4c60b1a2cdd096221) | downloaded 2026-10-25 (md5 verified); `fixes` rows streamed from the SQL dump (12,923 rows) | overlap check; fairness: also among our vulns published before 2024-07-23 (its NVD feed date) |
| Git history | blobless clones (`--filter=blob:none`) of the default branch + all refs | `code/clone.sh`, `data/raw/repos/` (gitignored) |

## 4. Linking (tiers)
- Vulnerability linked to a project: an NVD CVE with any reference URL under
  `github.com/<repo or alias>/`, or a GHSA published in the project's repo.
- Tier A (`commit_message`): commit message (any ref) matches `CVE-\d{4}-\d{4,}` or
  `GHSA(-[23456789cfghjmpqrvwx]{4}){3}` (case-insensitive). The cited ID need not be linked
  to the project (vendored-library fixes count); flag `id_linked_to_project`.
- Tier B (`nvd_ref`, `ghsa_text`): URL `github.com/<repo|alias>/commit/<sha>` in NVD
  references or in GHSA description/references; the SHA must resolve in the clone.
  Pull-request URLs `github.com/<repo|alias>/pull/<n>` are resolved with `gh api` to the
  PR's `merge_commit_sha` if the PR was merged (`nvd_pr`, `ghsa_pr`; cached in
  `data/raw/prs.json`). Linked vulnerabilities whose PR links resolve to nothing are
  counted as `pr_unresolved_vulns`. Squash/rebase merges (merge SHA has one parent): walk
  the first-parent chain back for as many commits as the PR had and keep those whose subject
  matches a PR commit subject (`gh api pulls/<n>/commits`); true merges keep the merge
  commit. Field `pr_commits` = commits contributed by the PR.
- Change scope (`change_scope`, from changed paths, `linking.change_scope`): `code` if any
  file is product code; `test` if only tests (+docs/CI); `doc_ci` if only docs, CI,
  Dockerfiles or requirements files. Added after a spot check found tier-A commits that only
  disclose a CVE in docs or pin CI dependencies. Core subset = `code`.
- Tier C: commit not in A or B whose subject/body matches the keyword list in
  `code/linking.py` (`KEYWORDS`). Unvalidated; released separately with a precision estimate.

## 5. Record schema (one row per (vulnerability, fix commit); full schema in data/release)
project, repo, vuln_id, cve_id, ghsa_id, cwe_ids, cvss_version, cvss_score, severity,
severity_source, published (earliest of NVD published / GHSA published), fix_commit,
parent_commits, commit_date (committer, UTC), files_changed, lines_added, lines_deleted
(diff against first parent), fix_to_publication_days (published - commit_date; negative =
fix after disclosure), tiers, link_sources, id_linked_to_project, nvd_url.
Also: pr_commits, change_scope.
Severity: NVD primary CVSS v3.1 > v3.0 > v4.0 > v2; else GHSA. `NVD-CWE-noinfo/Other` -> empty.
"Report" date is not public for most CVEs, so time is measured to publication only.

## 6. Statistics (descriptive only, `code/stats.py` -> results/results.json)
Per project and total: linked vulns, mapped vulns, coverage (mapped/linked), fix commits by
tier, A-B overlap, PR-only vulns; top CWEs; severity distribution; median/IQR of files,
lines, fix_to_publication_days; tier-C candidate count; tier-C precision with Wilson 95% CI
after the user labels the sample.

## 7. Validation sample (R10c)
Seed 20261025. Stratified by project, proportional, n = 200 (or all, if fewer) from tier C.
`data/validation_sample.csv` with blank `label` (security_fix / not_security_fix / unsure)
and `notes`. Claude does not label. Precision is reported only after the user labels.

## 8. Threats (to be written in the paper)
Tier A may include commits that mention a CVE without fixing it (tests, docs, reverts:
flagged `is_revert`); tier B depends on NVD reference quality; fixes in vendored copies;
squash vs merge histories; publication date is not report date; GitHub-only scope; keyword
list bias for tier C; snapshot date.

## 9. No-overlap note (R4)
P3 repo list = DL-based IDS research repos. P5 repo list = section 2. Disjoint by
construction; recorded in the shared notes folder for the P3 session.

## 10. Deviations / notes (2026-10-25)
- NVD totalResults grew 413,940 -> 413,944 during the paged download; pages are offset-based,
  so a few CVEs may be missed or duplicated at page edges (deduplicated by ID).
- References verified by DOI via Crossref (`verify_refs.py` DOI-only mode) because Semantic
  Scholar timed out; titles compared by eye with refs/candidates.csv. Devign removed (no
  Crossref DOI).
- After fresh review round 1 (review/review_round1.md): added CPE-based coverage
  (`code/coverage.py`; vendor:product list in the script), external overlap
  (`code/overlap_external.py`), C/C++ file counts, a second seeded sample of 100 tier-A/B
  records (`data/validation_sample_ab.csv`, seed 20261026) for link precision, and generated
  validation/overlap sentences (`paper/generated/{validation,overlap}.tex`).
- Project kinds unified to 4 categories (RTOS, net/protocol stack, firmware/SDK, crypto library).
- After fresh review round 2 (review/review_round2.md, weak accept): disclosure-channel
  counts, CPE column in Table I, gap median without Zephyr, strict single-commit count
  (default branch, non-merge), pool criteria stated, FAIR mapping, AI statement moved to
  Acknowledgment, bib titles brace-protected, CVEfixes overlap added.
- Labelling (R10c) was done by Claude subagents at the author's explicit request ("you do it",
  25 Oct 2026), not by a human; reported as such in the paper (Acknowledgment, Limitations,
  generated validation sentence). Evidence per row: commit message, file list, first 120 diff
  lines, vulnerability description (`code/label_bundle.py`).
- change_scope v2: SBOM / vulnerability-disposition files and .gitmodules count as doc_ci
  (found through the labels: ESP-IDF commits that only mark a CVE as not applicable).
