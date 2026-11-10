#!/usr/bin/env python3
"""Check what a corpus regeneration may and may not change.

A container change (for example SPEC 4.6.2's list-of-lists `txs`) may
rewrite every golden vector's bytes, but it must not change what a vector
pins, except where the rule being implemented moves it. The one moving
rule here is SPEC 3.7.5: TR is the MR of every transaction's id, the commit
transaction last, so a commit with two or more mutation transactions gets
a new TR, and with it a new CR and PR, and everything signed over them
afterwards (later arrows, their signatures and coz digests, ids naming a
PR).

For each vector in `tests/golden` at the base revision:

- A vector none of whose commits has two or more mutation transactions is
  stable: every value under a digest or signature field (commit_id, ar, sr,
  pr, cr, kr, tr, arrow, sig, czd, and each entry of `digests`) must still
  appear in it, at least as many times (a value repeated in a vector, such
  as a commit's PR and the expected PR, is counted each time).
- A vector with such a commit moves from that commit on: its lines before
  that commit must keep every value as above, and its key and state roots
  (kr, ar, sr), which TR does not reach, must all be kept. Its old and new
  expected tr, cr and pr are printed.

Added vectors are listed, not judged.

Usage, from the repository root:

    rs/fixture-gen/scripts/corpus-digests.py <base-revision>

Exits 0 when the rule holds, 1 otherwise (naming each vector and value
lost), 2 on a usage or git error.
"""

import collections
import json
import pathlib
import subprocess
import sys

FIELDS = {"commit_id", "ar", "sr", "pr", "cr", "kr", "tr", "arrow", "sig", "czd"}
ROOTS_TR_DOES_NOT_REACH = {"ar", "sr", "kr"}
CORPUS = "tests/golden"
COMMIT_CREATE = "/cyphr/commit/create"


def values(doc, out, only=None):
    """Collect (field, value) for every digest or signature in `doc`."""
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k in FIELDS and isinstance(v, str) and v:
                if only is None or k in only:
                    out[(k, v)] += 1
            elif k == "digests" and isinstance(v, list):
                if only is None or "czd" in only:
                    out.update(("czd", d) for d in v if isinstance(d, str))
            else:
                values(v, out, only)
    elif isinstance(doc, list):
        for v in doc:
            values(v, out, only)
    return out


def mutation_txs(line):
    """How many mutation transactions a bundle line holds, in either the
    flat (v1, one coz per transaction) or the nested (v2) `txs`."""
    count = 0
    for tx in line.get("txs", []):
        cozies = tx if isinstance(tx, list) else [tx]
        typs = [c.get("pay", {}).get("typ", "") for c in cozies]
        if not any(t.endswith(COMMIT_CREATE) for t in typs):
            count += 1
    return count


def first_moving_line(doc):
    """Index of the first commit line with two or more mutation
    transactions, or None."""
    for i, line in enumerate(doc.get("commits") or []):
        if mutation_txs(line) >= 2:
            return i
    return None


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
    lost, moved = [], []
    for path in sorted(old_files):
        old = json.loads(
            subprocess.run(["git", "show", f"{base}:{path}"], check=True,
                           capture_output=True, text=True).stdout)
        if path not in new_files:
            lost.append(f"{path}: vector removed")
            continue
        new = json.loads(pathlib.Path(path).read_text())
        new_values = values(new, collections.Counter())
        k = first_moving_line(old)
        if k is None:
            missing = values(old, collections.Counter()) - new_values
        else:
            kept = values((old.get("commits") or [])[:k], collections.Counter())
            kept += values(old, collections.Counter(), ROOTS_TR_DOES_NOT_REACH)
            missing = kept - new_values
            pair = lambda d, f: (d.get("expected") or {}).get(f)
            moved.append(f"{path}: " + ", ".join(
                f"{f} {pair(old, f)} -> {pair(new, f)}" for f in ("tr", "cr", "pr")))
        lost.extend(f"{path}: {k_} {v} lost" for k_, v in sorted(missing))
    for path in sorted(new_files - old_files):
        print(f"added: {path}")
    for line in moved:
        print(f"moved: {line}")
    for line in lost:
        print(line)
    print(f"{len(old_files)} vectors checked, {len(moved)} moved, {len(lost)} values lost")
    return 1 if lost else 0


if __name__ == "__main__":
    sys.exit(main())
