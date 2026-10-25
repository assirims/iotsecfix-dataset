# IoTSecFix datasheet

Follows "Datasheets for Datasets" (Gebru et al., CACM 2021). Numbers below are filled in by
`code/stats.py` from `results/results.json`; do not edit the generated `data/release/DATASHEET.md`.

## Motivation
- **Purpose.** A curated, link-level dataset of security-fixing commits in open-source IoT
  operating systems, firmware, protocol stacks and crypto libraries, for research on
  vulnerability-fix mining, patch analysis, vulnerability detection and security
  maintenance of embedded software. Existing fix datasets (Big-Vul, CVEfixes, MoreFixes,
  Project KB) are not built around IoT/embedded projects.
- **Creator.** Mohammed Assiri, Department of Computer Science, College of Computer Engineering
  and Sciences, Prince Sattam bin Abdulaziz University. **Funding.** FUNDING-PENDING (author to state).

## Composition
- **Instances.** `iotsecfix_fixes`: 2596 (vulnerability, fix commit) records covering
  686 vulnerabilities and 1985 distinct commits in 14
  projects. `iotsecfix_candidates`: 6846 unvalidated keyword-only candidate commits.
- **Projects.** Selected from a fixed pool of 19 repositories by rules I1-I3
  (PROTOCOL.md section 2); 1 excluded as inactive, 4 for fewer than
  5 mapped vulnerabilities, 0 by the 15-project cap.
- **Link tiers.** A = commit message cites the ID; B = NVD/GHSA URL points to the commit
  (or to a merged PR). Tier-A-only pairs: 590; tier-B-only: 1998;
  both: 8.
- **Coverage.** 576 of 804 vulnerabilities whose NVD/GHSA records point to a
  selected repo have at least one fix commit (71.6%).
- **Change scope.** code / test / doc_ci from changed paths; core subset (scope code):
  2214 records, 581 vulnerabilities.
- **Labels/fields.** See `iotsecfix_fixes.schema.json`. Severity and CWE come from NVD
  (fallback GHSA); 90.7% of vulnerabilities have a CWE.
- **Missing data.** Disclosure date unknown for some GHSA-only records; report date is not
  available (only publication date). CVSS absent for some recent CVEs (NVD backlog).
- **Noise.** Tier A can include commits that only mention an ID (tests, docs, backports,
  vendored-library updates: `id_linked_to_project = false`, 114 vulnerabilities).
  Tier C is unvalidated; precision is estimated on a labelled sample (see Validation).
- **Sensitive data.** Public commit metadata only (no author names or e-mails are released;
  the commit URL leads to public GitHub data). No personal data beyond that.

## Collection process
- Snapshot 2026-10-25. NVD CVE API 2.0 full catalogue (413944 CVE records),
  GitHub repository security advisories (via authenticated `gh api`), blobless git clones
  (586578 commits scanned in selected projects). Scripts in `code/`; run order in
  README / results/RUNLOG.md.

## Preprocessing
- Rejected CVEs dropped; withdrawn GHSAs dropped. `NVD-CWE-noinfo`/`NVD-CWE-Other` treated
  as missing. Diff stats against the first parent; binary files count as changed files with
  0 lines.

## Uses
- Fix-commit benchmarks for IoT code, patch-localisation evaluation, CWE profiles of
  embedded software, time-to-disclosure studies. **Not for:** claims about the absolute
  number of vulnerabilities in a project (silent fixes are missed) or about developers.

## Distribution and maintenance
- CSV + JSON + JSON Schema, scripts under an open-source license; DOI archive (Zenodo) on
  acceptance (MSR policy). Maintainer: TBD. Re-running the scripts regenerates a newer snapshot.

## Validation
A seeded sample of 100 records (half tier A, half tier B) is being labelled by the author to estimate link precision per tier. Tier C precision is not yet known: a seeded, project-stratified sample of 200 candidates is being labelled by the author.
