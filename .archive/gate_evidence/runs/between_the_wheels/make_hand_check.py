"""Render run 141's client edit log into the owner's HAND_CHECK format."""

from __future__ import annotations

import json
from pathlib import Path

TREE = Path(__file__).resolve().parents[3]
RUNDIR = Path(__file__).resolve().parent
OUT = TREE / "BUILD_PLANS_FIXES_2026-09-08" / "HAND_CHECK_T5_LIST_2026-09-17.md"
TARGET = "/Users/dev/Desktop/between_the_wheels"
SNAP = sorted((Path.home() / "CodeRadar_snapshots").glob("between_the_wheels_*"))[-1]

log = json.loads((RUNDIR / "client_edit_log.json").read_text())
stop = json.loads((RUNDIR / "phase5_stop.json").read_text())
shapes = [r for r in log if r["kind"] == "shape" and not r["reverted"]]
diffs = [r for r in log if r["kind"] == "diff" and not r["reverted"]]
back = [r for r in log if r["reverted"]]


def rule_of(rec: dict) -> str:
    role = rec.get("selected_role") or ""
    if role.startswith("solution_"):
        return role[len("solution_"):]
    ids = rec.get("rule_ids") or []
    return ids[0] if ids else "—"


def block(code: str, limit: int = 22) -> str:
    lines = (code or "").rstrip("\n").split("\n")
    if len(lines) > limit:
        lines = lines[:limit] + [f"    # … {len(lines) - limit} more line(s)"]
    return "```python\n" + "\n".join(lines) + "\n```"


def entry(n: int, rec: dict) -> str:
    rid = rec["row"]
    rel, func, line = rid.split("::")
    kind = "prescription — the CLIENT rendered the shape" if rec["kind"] == "shape" \
        else f"rewriter diff — `{rec['selected_role']}`"
    out = [
        f"## {n}. `{rel}:{line}` `{func}`  —  {rule_of(rec)}  ({rec['kind']})",
        "",
        f"**Row** `{rid}` · span `{rec['replace_span']}` · digest `{rec['digest']}` · "
        f"rules {', '.join(rec.get('rule_ids') or []) or '—'}",
        "",
        f"**Kind:** {kind}",
        "",
        f"**The row's own words (`fix`):** {rec['reason']}",
        "",
        "**Before:**",
        "",
        block(rec["before"]),
        "",
        "**After (what the client wrote into the target):**",
        "",
        block(rec["after"]),
        "",
    ]
    if rec.get("rendering_rationale"):
        out += [f"**The client's rendering of the `<placeholders>`:** {rec['rendering_rationale']}",
                ""]
    if rec.get("revert_note"):
        out += [f"**Backed out:** {rec['revert_note']}", ""]
    unreported = ("not reported — the row had left the live mirror by the time the client "
                  "reported (the repair cleared it; see the report)")
    out += [f"**Outcome reported:** `{rec.get('outcome') or unreported}`",
            "",
            "**Owner:** ",
            "",
            "---",
            ""]
    return "\n".join(out)


head = f"""# HAND CHECK — T5's applied solutions for the owner (2026-09-17, run 141 `between_the_wheels`)

Source: **run 141 `between_the_wheels`** — the end-to-end proof of the release form, with Claude Code
as the MCP client (packet §C row T5, ruling Q3: *the client edits, the server never writes the
target*). Unlike `HAND_CHECK_2026-09-15.md`, nothing here is quoted from a state file and left on
paper: **every `After` below is in the target's working tree right now**, written by the client.

- **Target (left standing for this check):** `{TARGET}`
- **COPY-FIRST snapshot (the before-state, byte for byte):** `{SNAP}`
- **Machine-readable edit log:** `.archive/runs/between_the_wheels/client_edit_log.json`
  (one record per row: file, span, rule ids, kind, role, digest, before, after, rendering
  rationale, outcome)
- **The whole difference:** `diff -rq` snapshot ↔ target names exactly the {stop.get('client_edits')}
  files this log names and nothing else — `cr_stop` reported `residue_clean: true`,
  `client_edits: {stop.get('client_edits')}`, `unexpected_changes: {json.dumps(stop.get('unexpected_changes'))}`.
- **The target's own runner before and after:** `-m pytest colorama/tests -q` through the wrapper,
  **exit 0 · 38 passed, 14 skipped** on both sides.

**{len(shapes) + len(diffs)} rows applied** — {len(shapes)} prescriptions the client rendered itself
(Part A, the ones I-75 is about: read these first) and {len(diffs)} rewriter diffs applied verbatim
(Part B) — over {len({r['file'] for r in log if not r['reverted']})} files. {len(back)} more were
applied and then **backed out** by the client because the target's own runner failed on them
(Part C); they are reported `failed` and the target holds the snapshot's bytes at those spans.

Write your verdict on the `Owner:` line of each (good / wrong / better = …).

---

# Part A — the {len(shapes)} prescriptions the client rendered (Q8 / I-75)

"""

body = [head]
n = 0
for rec in shapes:
    n += 1
    body.append(entry(n, rec))
body.append(f"\n# Part B — the {len(diffs)} rewriter diffs, applied verbatim\n\n")
for rec in diffs:
    n += 1
    body.append(entry(n, rec))
body.append(f"\n# Part C — the {len(back)} rows the client applied and BACKED OUT\n\n")
for rec in back:
    n += 1
    body.append(entry(n, rec))

OUT.write_text("".join(body), encoding="utf-8")
print(f"{OUT} — {n} entries ({len(shapes)} shapes, {len(diffs)} diffs, {len(back)} backed out), "
      f"{len(OUT.read_text().splitlines())} lines")
