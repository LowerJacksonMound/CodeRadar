#!/usr/bin/env python3
"""obs_run149_phase2_apply.py — RUN 149 `marathon`, THE CLIENT'S EDIT PASS.

The server never writes the target. This is the client applying, in the target's own working tree,
what `cr_apply` returned for each of the twelve that now HAS a repair. Diffs are applied as diffs.

  #21 has no row · #35 declined at the source (0 candidates) · #57 withheld by design
  #71 is prescribed and its shape is NOT determined (`<statement> # once` OR `for _ in range(<n>)`)
      — two readings, one of which the client must choose; skipped, and said so.

Rows are applied per file in DESCENDING span order so no earlier span drifts under a later edit,
and every byte changed is logged: file, span, role, digest, before → after.
"""
import json
import sys
from pathlib import Path

ROOT = Path("/Users/dev/Desktop/CODE_RADAR_REFURBISH")
sys.path.insert(0, str(ROOT))

from coderadar_mcp.write_tools import cr_apply   # noqa: E402

TARGET = Path("/Users/dev/Desktop/marathon")
RUNDIR = ROOT / ".archive" / "runs" / "marathon"
TWELVE = json.loads((RUNDIR / "phase1b_twelve.json").read_text())

APPLY = ["30", "33", "53", "61", "70", "73", "74", "75"]
SKIP = {"21": "no row at all — FIX_59 stopped the detector filing it",
        "35": "declined at the source (0 candidates) — FIX_58's three conditions",
        "57": "withheld by design — NAI-017 carries the reason as a registry field",
        "71": "prescribed; the shape is UNDETERMINED (`<statement> # once` OR `for _ in "
              "range(<n>): <statement>`) — which reading is right is the client's call, "
              "so nothing is rendered and nothing is applied"}


def parse_span(span: str) -> tuple[int, int]:
    _, _, tail = span.rpartition(":L")
    a, _, b = tail.partition("-L")
    return int(a), int(b)


def apply_hunks(diff: str, segment: list[str]) -> list[str]:
    """Apply a unified diff rendered over `segment` (the row's span) and return the new span."""
    out: list[str] = []
    cursor = 0
    lines = diff.splitlines(keepends=True)
    i = 0
    while i < len(lines) and not lines[i].startswith("@@"):
        i += 1
    while i < len(lines):
        head = lines[i]
        assert head.startswith("@@"), head
        old = head.split("-", 1)[1].split(" ", 1)[0]
        start = int(old.split(",")[0])
        out.extend(segment[cursor:start - 1])
        cursor = start - 1
        i += 1
        while i < len(lines) and not lines[i].startswith("@@"):
            ln = lines[i]
            if ln.startswith(" "):
                out.append(segment[cursor]); cursor += 1
            elif ln.startswith("-"):
                assert segment[cursor] == ln[1:], (segment[cursor], ln[1:])
                cursor += 1
            elif ln.startswith("+"):
                out.append(ln[1:])
            elif ln.startswith("\\"):
                pass
            i += 1
    out.extend(segment[cursor:])
    return out


def main() -> int:
    for t6, why in sorted(SKIP.items(), key=lambda kv: int(kv[0])):
        print(f"  #{t6:<3} NOT APPLIED — {why}")

    payloads = {}
    for t6 in APPLY:
        rid = TWELVE[t6]["row_id"]
        p = cr_apply(rid)
        payloads[t6] = p
        print(f"\ncr_apply #{t6} {rid}\n  kind={p.get('kind')} applies_cleanly={p.get('applies_cleanly')} "
              f"span={p.get('replace_span')} error={p.get('error')}")
        assert p.get("kind") == "diff" and p.get("applies_cleanly") is True, (t6, p.get("error"))
    (RUNDIR / "phase2_apply_payloads.json").write_text(json.dumps(payloads, indent=1, default=str))

    by_file: dict[str, list] = {}
    for t6, p in payloads.items():
        by_file.setdefault(p["file"], []).append((t6, p))

    log = []
    for rel, group in sorted(by_file.items()):
        group.sort(key=lambda tp: parse_span(tp[1]["replace_span"])[0], reverse=True)
        spans = sorted(parse_span(p["replace_span"]) for _, p in group)
        for (a1, b1), (a2, _) in zip(spans, spans[1:]):
            assert b1 < a2, f"{rel}: overlapping spans {a1}-{b1} / {a2}-"
        path = TARGET / rel
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        for t6, p in group:
            a, b = parse_span(p["replace_span"])
            segment = lines[a - 1:b]
            after = apply_hunks(p["diff"], segment)
            lines = lines[:a - 1] + after + lines[b:]
            log.append({"t6_row": int(t6), "row": p["row"], "file": rel,
                        "replace_span": p["replace_span"], "kind": p["kind"],
                        "selected_role": p["selected_role"], "digest": p["digest"],
                        "before": "".join(segment), "after": "".join(after)})
        path.write_text("".join(lines), encoding="utf-8")

    log.sort(key=lambda r: r["t6_row"])
    (RUNDIR / "client_edit_log_run149.json").write_text(json.dumps(log, indent=2))
    files = sorted({r["file"] for r in log})
    (RUNDIR / "client_edit_manifest_run149.txt").write_text("\n".join(files) + "\n")
    print(f"\nAPPLIED {len(log)} rows over {len(files)} files")
    for r in log:
        print(f"\n  #{r['t6_row']:<3} {r['file']} {r['replace_span']}  [{r['selected_role']}]")
        for l in r["before"].splitlines():
            print(f"        - {l}")
        for l in r["after"].splitlines():
            print(f"        + {l}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
