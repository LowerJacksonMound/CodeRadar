"""Run 141 — THE CLIENT'S EDIT PASS. Q3: the server never writes the target; this is the
client (Claude Code) applying, in the target's own working tree, what `cr_apply` returned.

  * a `diff` payload  → the unified diff is applied to the row's span, hunk by hunk;
  * a `shape` payload → the client's own rendering of the <placeholders> (client_renderings.json)
    replaces the row's span.

Rows are applied per file in DESCENDING span order so no earlier span drifts under a later edit,
and every byte changed is logged: file, span, rule ids, kind, role, digest, before, after.

    .venv_new/bin/python3 .archive/runs/between_the_wheels/client_apply.py
"""

from __future__ import annotations

import json
from pathlib import Path

RUNDIR = Path(__file__).resolve().parent
TARGET = Path("/Users/dev/Desktop/between_the_wheels")

payloads = json.loads((RUNDIR / "phase1_apply_payloads.json").read_text())
rows = {r["id"]: r for r in json.loads((RUNDIR / "phase1_rows.json").read_text())}
renderings = json.loads((RUNDIR / "client_renderings.json").read_text())


def parse_span(span: str) -> tuple[int, int]:
    _, _, tail = span.rpartition(":L")
    a, _, b = tail.partition("-L")
    return int(a), int(b)


def apply_hunks(diff: str, segment: list[str]) -> list[str]:
    """Apply a unified diff rendered over `segment` (the row's span) and return the new span."""
    out: list[str] = []
    cursor = 0                                   # 0-based index into `segment`
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


chosen: list[dict] = []
for p in payloads:
    if p["kind"] == "diff" and p.get("applies_cleanly") is True:
        chosen.append(p)
    elif p["kind"] == "shape" and p["row"] in renderings:
        chosen.append(p)

by_file: dict[str, list[dict]] = {}
for p in chosen:
    by_file.setdefault(p["file"], []).append(p)

log: list[dict] = []
for rel, group in sorted(by_file.items()):
    group.sort(key=lambda p: parse_span(p["replace_span"])[0], reverse=True)
    spans = sorted(parse_span(p["replace_span"]) for p in group)
    for (a1, b1), (a2, _) in zip(spans, spans[1:]):
        assert b1 < a2, f"{rel}: overlapping spans {a1}-{b1} / {a2}-"
    path = TARGET / rel
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    for p in group:
        start, end = parse_span(p["replace_span"])
        segment = lines[start - 1:end]
        if p["kind"] == "diff":
            after = apply_hunks(p["diff"], segment)
            rationale = None
        else:
            after = renderings[p["row"]]["after"].splitlines(keepends=True)
            rationale = renderings[p["row"]]["rationale"]
        lines = lines[:start - 1] + after + lines[end:]
        log.append({
            "row": p["row"], "file": rel, "replace_span": p["replace_span"],
            "rule_ids": rows[p["row"]]["rule_ids"], "kind": p["kind"],
            "selected_role": p["selected_role"], "digest": p["digest"],
            "reason": p["reason"], "before": "".join(segment), "after": "".join(after),
            "rendering_rationale": rationale,
        })
    path.write_text("".join(lines), encoding="utf-8")

log.sort(key=lambda r: (r["file"], parse_span(r["replace_span"])[0]))
(RUNDIR / "client_edit_log.json").write_text(json.dumps(log, indent=2))
files = sorted({r["file"] for r in log})
(RUNDIR / "client_edit_manifest.txt").write_text("\n".join(files) + "\n")
kinds: dict[str, int] = {}
for r in log:
    kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
print(f"APPLIED {len(log)} rows over {len(files)} files · {kinds}")
for f in files:
    n = sum(1 for r in log if r["file"] == f)
    print(f"  {n:2d}  {f}")
