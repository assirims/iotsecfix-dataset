"""Rewrite a PDF with only Title and Author in its metadata (no XMP, no producer/creator).

Usage: python code/clean_pdf.py <in.pdf> <out.pdf>
"""
import sys

from pypdf import PdfReader, PdfWriter

TITLE = "IoTSecFix: A Curated Dataset of Security-Fixing Commits in Open-Source IoT Software"
AUTHOR = "Mohammed Assiri"

reader = PdfReader(sys.argv[1])
writer = PdfWriter(clone_from=reader)
root = writer._root_object
if "/Metadata" in root:  # XMP stream
    del root["/Metadata"]
writer._info = None
writer.add_metadata({"/Title": TITLE, "/Author": AUTHOR})
with open(sys.argv[2], "wb") as f:
    writer.write(f)
