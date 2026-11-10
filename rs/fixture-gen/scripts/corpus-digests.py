#!/usr/bin/env python3
"""Check that a corpus regeneration kept every digest and signature.

A container change (for example SPEC 4.6.2's list-of-lists `txs`) may
rewrite every golden vector's bytes, but it must not change what any
existing vector pins. For each vector in `tests/golden` at the base
revision, every value under a digest or signature field (commit_id, ar,
sr, pr, cr, kr, tr, arrow, sig, czd, and each entry of `digests`) must
still appear in the same vector in the working tree, at least as many
times as it did (a value repeated in a vector, such as a commit's PR and
the expected PR, is counted each time). Added vectors are listed, not
judged.

Usage, from the repository root:

    rs/fixture-gen/scripts/corpus-digests.py <base-revision>

Exits 0 when every old value is kept, 1 otherwise (naming each vector and
value lost), 2 on a usage or git error.
"""

import collections
import json
import pathlib
import subprocess
import sys

FIELDS = {"commit_id", "ar", "sr", "pr", "cr", "kr", "tr", "arrow", "sig", "czd"}
CORPUS = "tests/golden"


def values(doc, out):
    """Collect (field, value) for every digest or signature in `doc`."""
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k in FIELDS and isinstance(v, str) and v:
                out[(k, v)] += 1
            elif k == "digests" and isinstance(v, list):
                out.update(("czd", d) for d in v if isinstance(d, str))
            else:
                values(v, out)
    elif isinstance(doc, list):
        for v in doc:
            values(v, out)
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    base = sys.argv[1]
    try:
        listed = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", base, CORPUS],
            check=True, capture_output=True, text=True,
        ).stdout.split()
    except subprocess.CalledProcessError as e:
        print(f"git ls-tree {base}: {e.stderr.strip()}", file=sys.stderr)
        return 2
    old_files = {p for p in listed if p.endswith(".json")}
    new_files = {str(p) for p in pathlib.Path(CORPUS).rglob("*.json")}
    lost = []
    for path in sorted(old_files):
        old = json.loads(
            subprocess.run(["git", "show", f"{base}:{path}"], check=True,
                           capture_output=True, text=True).stdout)
        if path not in new_files:
            lost.append(f"{path}: vector removed")
            continue
        new = json.loads(pathlib.Path(path).read_text())
        missing = values(old, collections.Counter()) - values(new, collections.Counter())
        lost.extend(f"{path}: {k} {v} lost" for k, v in sorted(missing))
    for path in sorted(new_files - old_files):
        print(f"added: {path}")
    for line in lost:
        print(line)
    print(f"{len(old_files)} vectors checked, {len(lost)} values lost")
    return 1 if lost else 0


if __name__ == "__main__":
    sys.exit(main())
