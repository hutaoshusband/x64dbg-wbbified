# -*- coding: utf-8 -*-
"""Generate the .hhk keyword index for the CHM build.

Sphinx's htmlhelp builder writes an empty x64dbgdoc.hhk because the docs
don't use index directives. This script fills it with one entry per page,
keyed by the page's <title>, so the CHM gets a usable Index tab.

Usage: python genhhk.py _build/htmlhelp/x64dbgdoc.hhp
Compatible with Python 2.7 (the portable build) and Python 3.
"""

from __future__ import print_function, unicode_literals

import io
import os
import re
import sys

TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)

ENTRY = (
    '<LI> <OBJECT type="text/sitemap">\n'
    '<param name="Name" value="{0}">\n'
    '<param name="Local" value="{1}">\n'
    "</OBJECT>\n"
)


def parse_files_section(hhp_path):
    files = []
    in_files = False
    with io.open(hhp_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("["):
                in_files = line == "[FILES]"
                continue
            if in_files and line:
                files.append(line)
    return files


def extract_title(html_path):
    with io.open(html_path, "rb") as f:
        data = f.read()
    # Sphinx (py2) occasionally emits cp1252 bytes in files declared utf-8
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("cp1252")
    match = TITLE_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


def escape_value(text):
    # Pure-ASCII output so hhc.exe (ANSI) and pyhhc agree on the encoding
    out = []
    for ch in text:
        if ch == '"':
            out.append("&quot;")
        elif ord(ch) > 126:
            out.append("&#{0};".format(ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


def main():
    if len(sys.argv) != 2:
        print("Usage: genhhk.py <project.hhp>")
        return 1

    hhp_path = sys.argv[1]
    base_dir = os.path.dirname(os.path.abspath(hhp_path))
    hhk_path = os.path.splitext(hhp_path)[0] + ".hhk"

    entries = []
    for rel in parse_files_section(hhp_path):
        if not rel.lower().endswith((".htm", ".html")):
            continue
        html_path = os.path.join(base_dir, rel.replace("\\", os.sep))
        if not os.path.isfile(html_path):
            print("warning: missing file: " + rel)
            continue
        title = extract_title(html_path)
        if not title:
            print("warning: no <title> in: " + rel)
            continue
        local = rel.replace("\\", "/")
        entries.append((title, local))

    entries.sort(key=lambda e: (e[0].lower(), e[1]))

    with io.open(hhk_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("<UL>\n")
        for title, local in entries:
            f.write(ENTRY.format(escape_value(title), local))
        f.write("</UL>\n")

    print("Wrote {0} index entries to {1}".format(len(entries), hhk_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
