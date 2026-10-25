"""Download the full NVD CVE catalogue via the NVD API 2.0 into data/raw/nvd/.

Pages of 2,000 CVEs are cached as data/raw/nvd/page_<startIndex>.json, so the run can be
resumed. Rate limit: without a key NVD allows 5 requests per rolling 30 s window; we sleep
6.5 s between requests (0.7 s if $NVD_API_KEY is set). The key is read from the environment
and sent only as the `apiKey` header; it is never printed or logged.

Usage: python code/nvd_fetch.py [<out-dir>]
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "data/raw/nvd")
    out.mkdir(parents=True, exist_ok=True)
    key = os.environ.get("NVD_API_KEY")
    headers = {"User-Agent": "iotsecfix-collector/0.1 (academic research)"}
    if key:
        headers["apiKey"] = key
    delay = 0.7 if key else 6.5
    start, total = 0, None
    t0 = time.time()
    while total is None or start < total:
        f = out / f"page_{start:07d}.json"
        if f.exists():
            data = json.loads(f.read_text())
            total = data["totalResults"]
            start += PAGE
            continue
        for attempt in range(8):
            try:
                r = requests.get(API, params={"startIndex": start, "resultsPerPage": PAGE},
                                 headers=headers, timeout=120)
            except requests.RequestException as e:
                print(f"start={start} attempt={attempt} error={type(e).__name__}", flush=True)
                time.sleep(15 * (attempt + 1))
                continue
            if r.status_code == 200:
                break
            print(f"start={start} attempt={attempt} http={r.status_code}", flush=True)
            time.sleep(15 * (attempt + 1))
        else:
            sys.exit(f"giving up at startIndex={start}")
        data = r.json()
        total = data["totalResults"]
        f.write_text(json.dumps(data))
        print(f"page start={start} n={len(data['vulnerabilities'])} total={total} "
              f"elapsed={time.time() - t0:.0f}s", flush=True)
        start += PAGE
        time.sleep(delay)
    meta = {"accessed_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "total_results": total, "api": API, "pages": len(list(out.glob("page_*.json")))}
    (out / "_meta.json").write_text(json.dumps(meta, indent=2))
    print(json.dumps(meta))


if __name__ == "__main__":
    main()
