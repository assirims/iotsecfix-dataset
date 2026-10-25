"""refs/refs.bib (verified, from verify_refs.py) -> paper/refs.bib with LaTeX-safe ASCII.

Only encodes characters (dashes, quotes, accents) and drops the `series` field (it repeats
the venue, e.g. "MSR '20") and braces titles; no bibliographic content is changed.
Usage: python code/clean_bib.py
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAP = {"–": "--", "’": "'", "′": "'", "Ś": "{\\'S}", "é": "{\\'e}", "è": "{\\`e}"}

s = (ROOT / "refs/refs.bib").read_text()
for a, b in MAP.items():
    s = s.replace(a, b)
s = re.sub(r"series=\{[^}]*\},\s*", "", s)
# protect title capitalisation (IEEEtran.bst lower-cases inproceedings titles)
s = re.sub(r"(\btitle=)\{([^{}]*)\}", r"\1{{\2}}", s)
bad = sorted({c for c in s if ord(c) > 127})
assert not bad, f"unmapped non-ASCII characters: {bad}"
(ROOT / "paper/refs.bib").write_text(s)
print("ok")
