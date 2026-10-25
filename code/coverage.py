"""Coverage against NVD's own product attribution (CPE) -> data/interim/coverage.json.

For each selected project, CVEs whose NVD configurations name one of the project's CPE
vendor:product pairs (CPE_PRODUCTS, chosen by listing all pairs that match the product name
and keeping the project's own; the matched pairs are written out for checking).
Usage: python code/coverage.py
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CPE_PRODUCTS = {
    "zephyr": ["zephyrproject:zephyr"],
    "wolfssl": ["wolfssl:wolfssl"],
    "esp-idf": ["espressif:esp-idf", "espressif:esp_idf"],
    "contiki-ng": ["contiki-ng:contiki-ng", "contiki-ng_project:contiki-ng"],
    "riot": ["riot-os:riot", "riot-os:riot-os"],
    "mongoose": ["cesanta:mongoose"],
    "netxduo": ["microsoft:azure_rtos_netx_duo", "eclipse:netx_duo", "eclipse:threadx_netx_duo"],
    "mosquitto": ["eclipse:mosquitto"],
    "open62541": ["open62541:open62541"],
    "mbedtls": ["arm:mbed_tls", "arm:mbedtls", "trustedfirmware:mbed_tls", "arm:mbed_crypto"],
    "micropython": ["micropython:micropython"],
    "esphome": ["esphome:esphome"],
    "nuttx": ["apache:nuttx"],
    "threadx": ["microsoft:azure_rtos_threadx", "eclipse:threadx", "microsoft:threadx"],
}
sys.path.insert(0, str(Path(__file__).resolve().parent))
import linking as L  # noqa: E402

CPE_RE = re.compile(r"^cpe:2\.3:[aoh]:([^:]+):([^:]+):")


def main() -> None:
    want = {vp: pid for pid, vps in CPE_PRODUCTS.items() for vp in vps}
    hits = defaultdict(dict)  # pid -> cve -> published
    cfg = {c["id"]: [c["repo"], *c["aliases"]]
           for c in json.loads((ROOT / "code/projects.json").read_text())["candidates"]}
    pats = {pid: L.repo_pattern(names) for pid, names in cfg.items()}
    reftypes = defaultdict(Counter)  # pid -> kind of GitHub reference URL
    seen = Counter()
    for f in sorted((ROOT / "data/raw/nvd").glob("page_*.json")):
        for v in json.loads(f.read_text())["vulnerabilities"]:
            c = v["cve"]
            if c.get("vulnStatus") == "Rejected":
                continue
            for r in c.get("references", []):
                u = r["url"]
                for pid, pat in pats.items():
                    if pat.search(u):
                        m = re.search(r"github\.com/[^/]+/[^/]+/([^/#?]+)", u)
                        reftypes[pid][m.group(1) if m else "root"] += 1
            for conf in c.get("configurations", []):
                for node in conf.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        mm = CPE_RE.match(m.get("criteria", ""))
                        if mm and m.get("vulnerable", True):
                            vp = f"{mm.group(1)}:{mm.group(2)}"
                            if vp in want:
                                seen[vp] += 1
                                hits[want[vp]][c["id"]] = c["published"]
    interim = json.loads((ROOT / "data/interim/projects.json").read_text())
    out = {"pairs_found": dict(seen), "projects": {}}
    for p in interim["projects"]:
        if not p["selected"]:
            continue
        cpe = hits.get(p["id"], {})
        mapped = {f["vuln_id"] for f in p["fixes"]}
        out["projects"][p["id"]] = {
            "cpe_cves": len(cpe), "cpe_mapped": len(set(cpe) & mapped),
            "cpe_before_2017": sum(d[:4] < "2017" for d in cpe.values()),
            "cpe_before_2017_mapped": sum(d[:4] < "2017" and k in mapped for k, d in cpe.items()),
            "nvd_github_ref_types": dict(reftypes[p["id"]])}
    (ROOT / "data/interim/coverage.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
