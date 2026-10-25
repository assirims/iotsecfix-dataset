"""Toy examples checked by hand. Run: shared/.venv/bin/python -m pytest p5-msr-data/code/tests"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import linking as L  # noqa: E402

REPOS = ["zephyrproject-rtos/zephyr", "eclipse/mosquitto"]


def test_find_ids():
    cves, ghsas = L.find_ids("net: fix cve-2023-4264 and CVE-2021-3581, see GHSA-Rf6Q-RHHP-pqhf")
    assert cves == {"CVE-2023-4264", "CVE-2021-3581"}
    assert ghsas == {"GHSA-rf6q-rhhp-pqhf"}
    assert L.find_ids("CVE-23-1 GHSA-aaaa-bbbb-cccc") == (set(), set())  # bad formats


def test_commit_urls():
    t = ("https://github.com/zephyrproject-rtos/zephyr/commit/ABCDEF1234567 and "
         "https://github.com/eclipse/mosquitto/pull/12/commits/" + "a" * 40 + " and "
         "https://github.com/zephyrproject-rtos/zephyr-other/commit/1234567890 and "
         "https://github.com/zephyrproject-rtos/zephyr/pull/55")
    assert L.commit_urls(t, REPOS) == {"abcdef1234567", "a" * 40}
    assert L.pr_urls(t, REPOS) == {55, 12}


def test_repo_pattern_boundary():
    p = L.repo_pattern(["FreeRTOS/FreeRTOS-Kernel"])
    assert p.search("https://github.com/FreeRTOS/FreeRTOS-Kernel/security")
    assert p.search("https://github.com/freertos/freertos-kernel")
    assert not p.search("https://github.com/FreeRTOS/FreeRTOS-Kernel-Partner-Supported-Demos")
    assert not L.repo_pattern(["FreeRTOS/FreeRTOS"]).search("github.com/FreeRTOS/FreeRTOS-Kernel")


def test_keywords():
    assert L.keyword_hits("net: ip: fix out-of-bounds read in ipv6 parser") == ["out of bounds"]
    assert set(L.keyword_hits("Fix heap overflow found by OSS-Fuzz")) == {
        "heap/stack overflow", "fuzzing"}
    assert L.keyword_hits("docs: fix typo in README") == []
    assert L.keyword_hits("add missing length check on rx frame") == ["bounds check"]


def test_revert():
    assert L.is_revert('Revert "net: fix CVE-2020-1"')
    assert not L.is_revert("net: revert-safe parser")


def test_nvd_fields():
    cve = {"metrics": {
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
            {"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
        "weaknesses": [{"description": [{"value": "NVD-CWE-noinfo"}]},
                       {"description": [{"value": "CWE-787"}, {"value": "CWE-787"}]}]}
    assert L.nvd_severity(cve) == ("3.1", 7.5, "HIGH")
    assert L.nvd_severity({"metrics": {}}) == ("", None, "")
    assert L.nvd_cwes(cve) == ["CWE-787"]


def test_ghsa_severity():
    adv = {"severity": "high", "cvss_severities": {"cvss_v3": {"score": 7.0}, "cvss_v4": {"score": None}}}
    assert L.ghsa_severity(adv) == ("3.x", 7.0, "HIGH")
    assert L.ghsa_severity({"severity": "low"}) == ("", None, "LOW")


def test_days_between():
    # commit 2024-01-01T00:00Z (epoch 1704067200), published 2024-01-11T12:00 -> 10.5 days
    assert L.days_between("2024-01-11T12:00:00.000", 1704067200) == 10.5
    assert L.days_between("2023-12-31T00:00:00Z", 1704067200) == -1.0


def test_stats_helpers():
    import stats
    assert stats.q([1, 2, 3, 4, 5]) == {"median": 3.0, "qOne": 2.0, "qThree": 4.0}
    lo, hi = stats.wilson(8, 10)  # textbook value: 0.490 .. 0.943
    assert round(lo, 3) == 0.490 and round(hi, 3) == 0.943
    fx = [{"vuln_id": "V1", "fix_commit": "a", "tiers": "A;B", "files_changed": 2, "lines_added": 3,
           "lines_deleted": 1, "commit_date": "2020-01-01", "fix_to_publication_days": 5.0},
          {"vuln_id": "V1", "fix_commit": "b", "tiers": "A", "files_changed": 4, "lines_added": 10,
           "lines_deleted": 0, "commit_date": "2020-02-01", "fix_to_publication_days": -26.0},
          {"vuln_id": "V2", "fix_commit": "a", "tiers": "B", "files_changed": 2, "lines_added": 3,
           "lines_deleted": 1, "commit_date": "2020-01-01", "fix_to_publication_days": None}]
    s = stats.summarise(fx)
    assert (s["vulns"], s["records"], s["fixCommits"]) == (2, 3, 2)
    assert (s["tierAOnly"], s["tierBOnly"], s["tierAB"]) == (1, 1, 1)
    assert s["lagN"] == 1 and s["lagDays"]["median"] == 5.0  # earliest fix of V1 only
    assert s["linesChanged"]["median"] == 7.0  # commits a (4) and b (10)
    assert (s["scopeCode"], s["scopeDocCi"]) == (0, 0)  # no change_scope key in toy rows


def test_allocate():
    import sample
    assert sample.allocate({"x": 90, "y": 10}, 20) == {"x": 18, "y": 2}
    a = sample.allocate({"x": 1000, "y": 1, "z": 0}, 10)
    assert a == {"x": 9, "y": 1, "z": 0}
    assert sample.allocate({"x": 3, "y": 2}, 10) == {"x": 3, "y": 2}


def test_change_scope():
    assert L.change_scope(["doc/security/vulnerabilities.rst"]) == "doc_ci"
    assert L.change_scope(["scripts/ci/requirements-actions.txt", ".github/workflows/x.yml"]) == "doc_ci"
    assert L.change_scope(["tests/net/ipv6/src/main.c", "doc/a.md"]) == "test"
    assert L.change_scope(["subsys/net/ip/ipv6.c", "tests/net/ipv6/src/main.c"]) == "code"
    assert L.change_scope(["README.md"]) == "doc_ci"
    assert L.change_scope([]) == "doc_ci"
