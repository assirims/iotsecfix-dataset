# IoTSecFix datasheet

Follows "Datasheets for Datasets" (Gebru et al., CACM 2021). Numbers below are filled in by
`code/stats.py` from `results/results.json`; do not edit the generated `data/release/DATASHEET.md`.

## Motivation
- **Purpose.** A curated, link-level dataset of security-fixing commits in open-source IoT
  operating systems, firmware, protocol stacks and crypto libraries, for research on
  vulnerability-fix mining, patch analysis, vulnerability detection and security
  maintenance of embedded software. Existing fix datasets (Big-Vul, CVEfixes, MoreFixes,
  Project KB) are not built around IoT/embedded projects.
- **Creator.** Mohammed Assiri, Department of Mechanical Engineering, College of Engineering,
  Prince Sattam bin Abdulaziz University. **Funding.** None.

## Composition
- **Instances.** `iotsecfix_fixes`: {total[records]} (vulnerability, fix commit) records covering
  {total[vulns]} vulnerabilities and {total[fixCommits]} distinct commits in {selectedProjects}
  projects. `iotsecfix_candidates`: {total[candidates]} unvalidated keyword-only candidate commits.
- **Projects.** Selected from a fixed pool of {poolSize} repositories by rules I1-I3
  (PROTOCOL.md section 2); {excludedInactive} excluded as inactive, {excludedFewVulns} for fewer than
  5 mapped vulnerabilities, {excludedRank} by the 15-project cap.
- **Link tiers.** A = commit message cites the ID; B = NVD/GHSA URL points to the commit
  (or to a merged PR). Tier-A-only pairs: {total[tierAOnly]}; tier-B-only: {total[tierBOnly]};
  both: {total[tierAB]}.
- **Coverage.** {total[linkedMapped]} of {total[linkedVulns]} vulnerabilities whose NVD/GHSA records point to a
  selected repo have at least one fix commit ({total[coveragePct]}%).
- **Change scope.** code / test / doc_ci from changed paths; core subset (scope code):
  {total[core][records]} records, {total[core][vulns]} vulnerabilities.
- **Labels/fields.** See `iotsecfix_fixes.schema.json`. Severity and CWE come from NVD
  (fallback GHSA); {total[withCwePct]}% of vulnerabilities have a CWE.
- **Missing data.** Disclosure date unknown for some GHSA-only records; report date is not
  available (only publication date). CVSS absent for some recent CVEs (NVD backlog).
- **Noise.** Tier A can include commits that only mention an ID (tests, docs, backports,
  vendored-library updates: `id_linked_to_project = false`, {total[citedNotLinked]} vulnerabilities).
  Tier C is unvalidated; precision is estimated on a labelled sample (see Validation).
- **Sensitive data.** Public commit metadata only (no author names or e-mails are released;
  the commit URL leads to public GitHub data). No personal data beyond that.

## Collection process
- Snapshot {snapshotDate}. NVD CVE API 2.0 full catalogue ({nvdCves} CVE records),
  GitHub repository security advisories (via authenticated `gh api`), blobless git clones
  ({commitsScanned} commits scanned in selected projects). Scripts in `code/`; run order in
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
VALIDATION_SECTION
