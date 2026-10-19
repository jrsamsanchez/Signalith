#!/usr/bin/env python3
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
"""Add the copyright and SPDX license lines to every source file that lacks them.

Run from the repository root: python3 .github/scripts/add-license-headers.py
It changes only tracked source files outside testdata/, and leaves a file
alone when it already has an SPDX-License-Identifier line.
"""
import subprocess
import sys

COPYRIGHT = "Copyright 2026 The Signalith authors"
SPDX = "SPDX-License-Identifier: Apache-2.0"

# Comment style per extension: (line prefix, block open, block close).
STYLES = {
    ".go": ("// ", None, None),
    ".js": ("// ", None, None),
    ".css": (None, "/* ", " */"),
    ".sh": ("# ", None, None),
    ".ps1": ("# ", None, None),
    ".py": ("# ", None, None),
    ".tf": ("# ", None, None),
}


def header(ext):
    prefix, open_, close = STYLES[ext]
    if prefix:
        return f"{prefix}{COPYRIGHT}\n{prefix}{SPDX}\n"
    return f"{open_}{COPYRIGHT}{close}\n{open_}{SPDX}{close}\n"


def files():
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    for path in out.splitlines():
        if "/testdata/" in path or path.startswith("testdata/"):
            continue
        for ext in STYLES:
            if path.endswith(ext):
                yield path, ext


def main():
    check = "--check" in sys.argv
    missing = []
    for path, ext in files():
        with open(path, encoding="utf-8", newline="") as f:
            text = f.read()
        if SPDX in text[:2000]:
            continue
        missing.append(path)
        if check:
            continue
        nl = "\r\n" if "\r\n" in text[:2000] else "\n"
        head = header(ext).replace("\n", nl)
        if text.startswith("#!"):
            first, _, rest = text.partition("\n")
            text = first + "\n" + head + rest
        else:
            # Go needs a blank line so the header is not read as package docs.
            sep = nl if ext == ".go" else ""
            text = head + sep + text
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    if check and missing:
        print("missing license header:\n  " + "\n  ".join(missing))
        sys.exit(1)
    if not check:
        print(f"added headers to {len(missing)} files")


if __name__ == "__main__":
    main()
