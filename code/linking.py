"""Pure functions that turn text and NVD/GHSA records into dataset fields (unit-tested)."""
import re
from datetime import datetime, timezone

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.I)
SHA_RE = r"[0-9a-f]{7,40}"

# Tier C. Word-bounded, case-insensitive. Kept deliberately specific: generic words such as
# "fix", "crash" or "leak" alone are excluded because they match most maintenance commits.
KEYWORDS = {
    "buffer overflow": r"buffer[ -]?(?:over|under)(?:flow|run|read|write)",
    "out of bounds": r"out[ -]of[ -]bounds?|\boob\b",
    "use after free": r"use[ -]after[ -]free|\buaf\b",
    "double free": r"double[ -]free",
    "null dereference": r"null(?: pointer)?[ -]deref",
    "integer overflow": r"integer (?:over|under)flow|int(?:eger)? wrap",
    "heap/stack overflow": r"(?:heap|stack)[ -](?:buffer[ -])?overflow|stack smash",
    "vulnerability": r"vulnerab",
    "security": r"\bsecurity\b|\bsecure? fix",
    "exploit": r"\bexploit",
    "malicious input": r"malicious|crafted (?:packet|frame|message|input|payload)|attacker",
    "denial of service": r"denial[ -]of[ -]service|\bdos\b|infinite loop",
    "injection": r"\binjection\b",
    "info leak": r"info(?:rmation)? (?:leak|disclosure)|uninitiali[sz]ed (?:memory|stack|data)",
    "fuzzing": r"oss-?fuzz|\bfuzz(?:er|ing)?\b",
    "cwe": r"\bcwe-\d+",
    "race condition": r"race condition|toctou",
    "bounds check": r"(?:missing|add|fix|improve)\w* (?:\w+ )?(?:bounds?|length|size) (?:check|validation)",
}
_KW = {k: re.compile(v, re.I) for k, v in KEYWORDS.items()}


def find_ids(text: str) -> tuple[set[str], set[str]]:
    """CVE and GHSA IDs in `text`, normalised (CVE upper-case, GHSA lower-case body)."""
    cves = {f"CVE-{y}-{n}" for y, n in CVE_RE.findall(text or "")}
    ghsas = {"GHSA" + m[4:].lower() for m in GHSA_RE.findall(text or "")}
    return cves, ghsas


def repo_pattern(repos: list[str]) -> re.Pattern:
    alt = "|".join(re.escape(r) for r in repos)
    return re.compile(rf"github\.com/(?:{alt})(?=[/#?]|$|\s|\)|\]|\")", re.I)


def commit_urls(text: str, repos: list[str]) -> set[str]:
    """SHAs of github.com/<repo>/commit/<sha> (also /commits/<sha>, /pull/N/commits/<sha>)."""
    alt = "|".join(re.escape(r) for r in repos)
    pat = re.compile(rf"github\.com/(?:{alt})/(?:pull/\d+/)?commits?/({SHA_RE})(?![0-9a-f])", re.I)
    return {s.lower() for s in pat.findall(text or "")}


def pr_urls(text: str, repos: list[str]) -> set[int]:
    alt = "|".join(re.escape(r) for r in repos)
    pat = re.compile(rf"github\.com/(?:{alt})/pull/(\d+)", re.I)
    return {int(n) for n in pat.findall(text or "")}


def keyword_hits(message: str) -> list[str]:
    return [k for k, rx in _KW.items() if rx.search(message or "")]


def is_revert(message: str) -> bool:
    return bool(re.match(r"\s*(?:revert\b|\"?revert \")", message or "", re.I))


def nvd_severity(cve: dict) -> tuple[str, float | None, str]:
    """(cvss_version, base_score, severity) from an NVD 2.0 `cve` object; Primary first."""
    metrics = cve.get("metrics", {})
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                     ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")):
        ms = metrics.get(key) or []
        if not ms:
            continue
        ms = sorted(ms, key=lambda m: m.get("type") != "Primary")
        d = ms[0]["cvssData"]
        sev = d.get("baseSeverity") or ms[0].get("baseSeverity") or ""
        return ver, d.get("baseScore"), sev.upper()
    return "", None, ""


def nvd_cwes(cve: dict) -> list[str]:
    out = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in out:
                out.append(v)
    return out


def ghsa_severity(adv: dict) -> tuple[str, float | None, str]:
    cv = adv.get("cvss_severities") or {}
    for key, ver in (("cvss_v3", "3.x"), ("cvss_v4", "4.0")):
        c = cv.get(key) or {}
        if c.get("score"):
            return ver, c["score"], (adv.get("severity") or "").upper()
    return "", None, (adv.get("severity") or "").upper()


def parse_ts(s: str) -> datetime:
    """ISO date/time (NVD has no zone, GHSA ends in Z) -> aware UTC datetime."""
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days_between(published: str, commit_epoch: int) -> float:
    """published - commit time, in days (positive = fix committed before disclosure)."""
    c = datetime.fromtimestamp(commit_epoch, tz=timezone.utc)
    return round((parse_ts(published) - c).total_seconds() / 86400, 2)


_DOC = re.compile(r"(?:^|/)(?:docs?|documentation)/|\.(?:md|rst|adoc|txt\.in)$|"
                  r"(?:^|/)(?:README|CHANGELOG|ChangeLog|NEWS|RELEASE[^/]*|SECURITY)[^/]*$", re.I)
_CI = re.compile(r"^\.(?:github|gitlab|circleci|ci)/|^\.gitlab-ci|(?:^|/)ci/|"
                 r"(?:^|/)requirements[^/]*\.txt$|(?:^|/)Dockerfile$|^\.pre-commit", re.I)
_TEST = re.compile(r"(?:^|/)(?:tests?|testing|unittests?|fuzz(?:ing)?)/|(?:^|/)test_[^/]*$", re.I)


def change_scope(paths: list[str]) -> str:
    """'code' if any changed file is product code; else 'test' if any test file; else 'doc_ci'."""
    if not paths:
        return "doc_ci"
    kinds = {"doc_ci" if (_DOC.search(p) or _CI.search(p)) else "test" if _TEST.search(p) else "code"
             for p in paths}
    return "code" if "code" in kinds else "test" if "test" in kinds else "doc_ci"
