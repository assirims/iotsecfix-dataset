# Labelling the tier-C sample (for Dr. Assiri, R10c) — about 3-4 hours for 200 rows

File: `data/validation_sample.csv` (seed 20261025, stratified by project). Claude does not label.

For each row open `commit_url`, read the message and the diff, then fill:

- `label` — exactly one of:
  - `security_fix`: the change removes a weakness an attacker could trigger (memory-safety
    bug on input handling, missing bounds/length check, auth/crypto flaw, DoS on malformed
    input, info leak). Hardening that closes a concrete attack path counts.
  - `not_security_fix`: refactoring, docs, tests only, features, non-exploitable bugs,
    false keyword match (e.g. "DOS file system").
  - `unsure`: cannot decide in ~2 minutes.
- `notes` — optional, one short phrase (e.g. "fuzz-found OOB read in parser").

Rules: judge the commit only, not the project. Do not change other columns or row order.
When done, tell the P5 session; `code/stats.py` then computes precision with a Wilson 95% CI
(`unsure` counts as not confirmed).
Tip: do 50 rows per sitting; save after each sitting.

---
# Part 2: link precision sample (tiers A and B) — about 2-3 hours for 100 rows

File: `data/validation_sample_ab.csv` (seed 20261026; 50 tier-A-only and 50 tier-B records).
For each row open `advisory_url` (what the vulnerability is) and `commit_url` (the commit), then fill
`label` with exactly one of:
- `fixes_vulnerability`: the commit contains (part of) the code change that removes this vulnerability.
- `part_of_fix`: the commit belongs to the fix delivery (e.g. the test or a refactoring inside the fix PR) but holds no fixing code itself.
- `not_fix`: unrelated to fixing this vulnerability (e.g. a release note, a CI dependency bump that
  mentions the ID, a different bug).
- `unsure`.
Precision reported per tier = (fixes_vulnerability + part_of_fix) / n, with a Wilson 95% CI.
A backport that contains the fixing code counts as `fixes_vulnerability`.
