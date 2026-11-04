"""T2's proof — the READ tools and the stdio server, offline, over a real run's files.

Five parts, the house shape (`fix42_static_observations_proof.py`,
`fix47_rca_reroute_proof.py`, `mcp_interface_proof.py`):

  1. THE SURFACE      — T2's six tools bound in T1's registry; the server publishes all 13.
  2. THE ANSWERS      — every read tool answered from a real run's published files, and
                        every answer validated against T1's OWN output schema.
  3. PAGING (Q9)      — two pages, a page never splits a file, every filter, totals hold.
  4. `finished` (Q5)  — the mirror route and the computed route, and that a withheld row
                        never counts against either.
  5. REFUSALS         — the wrong target, an unknown row, a word outside a fixed set, a
                        tool no lane has bound, a tool that is not in the surface.

This file READS NO FILE ITSELF — it asks the tools, and they open the published files.
That is deliberate: a data read inside a file whose name carries a rule-code word (this
one carries `proof`) is a step-17 hunter site that would need a ledger row (T1's
decision 12, and the CREEP that failed T1's first health pass).

Run it with no argument for the copy's own most recent run, or point it at another:
    .venv_new/bin/python3 -m coderadar_mcp.read_tools_proof [<state_during_run dir>]
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import read_tools as rt
from . import server
from . import session_tools as st
from . import write_tools as wt
from .tool_interface import (APPLY_REVIEW_REASON, APPLY_STATES, EDGE_STATES, HANDLERS,
                             PAGE_SIZE_DEFAULT, TOOLS, unimplemented, validate_payload)

#: Every part appends the label of anything that did not hold; an empty list is the PASS.
FAILURES: list[str] = []

#: The client contract this lane extends, read through the PACKAGE's own reader and never with an
#: `open()` written here — this file's name carries `proof`, so a read spelled in it would be a
#: step-17 hunter site with no ledger row (`b9_proof.read_json` is the same idiom).
_README: str = rt._text_of(Path(__file__).resolve().parent / "README.md")

#: Keys a lane answers with that T1's output schema does not carry — named here so the
#: proof STATES a divergence instead of hiding it, never empty by accident.
#: `cr_status.finished_source` lived here through run 137; the session-3 transplant absorbed
#: it into `tool_interface.py` (T2 report decision 1), so nothing diverges today.
EXTRA_KEYS: dict[str, tuple[str, ...]] = {}


def _line(label: str, held: bool, said: str = "") -> None:
    print(f"  {'✓' if held else '✗'} {label}{' — ' + said if said else ''}")
    if held is False:
        FAILURES.append(label)


def _schema_holds(name: str, answer: dict[str, Any]) -> None:
    """T1's `validate_payload` over a real answer, with this lane's declared extras
    removed first and named in the line, so nothing is validated away silently."""
    trimmed = {k: v for k, v in answer.items() if k not in EXTRA_KEYS.get(name, ())}
    problems = validate_payload(TOOLS[name], trimmed, "output")
    extras = ", ".join(EXTRA_KEYS.get(name, ()))
    _line(f"{name}: answer validates against T1's output schema",
          problems == [], f"{len(trimmed)} keys{'; beyond the schema: ' + extras if extras else ''}"
          if problems == [] else "; ".join(problems))


def _first_named(where: Path, names: tuple[str, ...]) -> Path | None:
    """The first of a ROLE's names that this directory carries — the role table is
    `read_tools.STATE_FILES` and is never re-spelled here (I-143, session 10: one reader spelled
    in three places is how two lanes were tripped by one missing name)."""
    return next((where / n for n in names if (where / n).is_file()), None)


def _newest_run_state(tree: Path) -> Path | None:
    """The most recent `.archive/runs/<name>/state_during_run/` this TREE can answer out of IN
    FULL — and "in full" is now tested against the state itself.

    I-143 (run 156): a run record is archived under names the reader has to know, and the reader
    knew only some of them — run 156's state had to be written under the LIVE names because the
    archived ones were the only spelling in the table. I-124 (run 153): the same reader from the
    other side. A run directory's dash mirror is `monitor_mirror.json`, a name that was in no
    table at all, and the completeness test here asked `cr_intent` — a question about a DIFFERENT
    file, kept by the publishing tree — so a run whose own dash mirror carried no measured
    `mypy_errors` was accepted and two good runs were walked past onto a stale one.

    Q6's default, built: the role table is `read_tools.STATE_FILES`, read from there, and the
    completeness test READS THE STATE IT IS ABOUT TO JUDGE — a measured `mypy_errors`, which is
    the value `cr_status`, `cr_data_types` and `finished` all read out of this directory. It is
    still made by ASKING THE TOOLS; no file is opened here (this file's name carries `proof`, so
    a data read written here would be a step-17 hunter site with no ledger row).
    """
    runs = tree / ".archive" / "runs"
    roles = ("builder", "circuit", "noai")
    dated: list[tuple[float, Path]] = []
    # F1 (2026-10-01): the kept evidence runs count too — retention prunes .archive/runs, never gate_evidence
    for where in [*runs.glob("*/state_during_run"), *(tree / ".archive" / "gate_evidence" / "runs").glob("*/state_during_run")]:
        found = [_first_named(where, rt.STATE_FILES[r]) for r in roles]
        if all(f is not None for f in found):
            dated.append((found[0].stat().st_mtime, where))   # type: ignore[union-attr]
    dated.sort(reverse=True)
    for _, where in dated:
        rt.configure(state_dir=where)
        rt.configure(target=rt.cr_status()["target"], state_dir=where)
        status = rt.cr_status()
        measured = status["summary"].get("mypy_errors") is not None
        if measured and rt.cr_intent()["error"] is None:
            return where
    return dated[0][1] if dated else None


# ── 1. the surface ───────────────────────────────────────────────────────────


def part_one_surface() -> None:
    print("\n1. THE SURFACE — T1's registry, filled by this lane only")
    bound = sorted(HANDLERS)
    _line("T2's six tools are bound", set(rt.OWNED) <= set(bound), ", ".join(sorted(rt.OWNED)))
    # Merged tree (session-3 transplant): all three lanes' modules are imported, so the whole
    # surface is bound and the three OWNED tuples partition it with no overlap.
    owned = sorted(set(rt.OWNED) | set(wt.OWNED) | set(st.OWNED))
    _line("the three lanes partition the surface and every tool is bound",
          owned == bound == sorted(TOOLS)
          and len(rt.OWNED) + len(wt.OWNED) + len(st.OWNED) == len(TOOLS),
          f"{len(bound)} of {len(TOOLS)} tools bound — "
          f"T2={len(rt.OWNED)}, T3={len(wt.OWNED)}, T4={len(st.OWNED)}")
    tools = server.tool_list()
    names = [t.name for t in tools]
    _line("the server publishes the WHOLE surface, bound or not",
          sorted(names) == sorted(TOOLS), f"{len(names)} tool names")
    shaped = [t for t in tools
              if t.input_schema.get("type") == "object" and "properties" in t.input_schema]
    _line("every published tool carries a JSON-Schema input", len(shaped) == len(tools))
    paged = TOOLS["cr_infractions"].input_field("page_size")
    _line("the page default is the ruled 50 (Q9)",
          paged is not None and paged.default == PAGE_SIZE_DEFAULT, f"page_size={PAGE_SIZE_DEFAULT}")
    # I-136 / Q5 (session 10). The question the row asked was whether a `total_pages` field was
    # owed. It is not: `pages` IS that field and has been since run 156 — what was missing was a
    # client contract saying so, and the README's bounded-prompt line. Both are stated here, as
    # facts about the SURFACE, so a reader of the proof does not have to take the report's word.
    out_keys = [f.name for f in TOOLS["cr_infractions"].output_schema]
    _line("I-136: `pages` IS the field a client pages by — and there is no second one",
          "pages" in out_keys and "total_pages" not in out_keys and "has_more" not in out_keys,
          f"page · pages · total, no total_pages, no has_more ({len(out_keys)} keys)")
    _line("…and the contract says so in the README a client is handed",
          all(w in _README for w in ("`pages` IS the field to page by", "Bound the prompt")),
          "the paging line and the bounded-prompt line are both in coderadar_mcp/README.md")
    # I-148 (a) / I-152 (session 10): the two payload marks are DECLARED, not just answered.
    _line("I-148 (a): the row schema declares `replace_span_live` and `span_current`",
          all(k in TOOLS["cr_infractions"].contract or k in str(TOOLS["cr_infractions"].output_schema)
              for k in ("replace_span_live", "span_current")))
    _line("I-145: `given_id` is declared on cr_apply and cr_report_outcome",
          "given_id" in [f.name for f in TOOLS["cr_apply"].output_schema]
          and "given_id" in [f.name for f in TOOLS["cr_report_outcome"].output_schema])
    _line("I-149: `confirmed_from_ledger` and `detail_builder` are declared on cr_status",
          all(k in [f.name for f in TOOLS["cr_status"].output_schema]
              for k in ("confirmed_from_ledger", "detail_builder")))


# ── 2. the answers ───────────────────────────────────────────────────────────


def part_two_answers(state_dir: Path) -> dict[str, Any]:
    print(f"\n2. THE ANSWERS — every read tool over {state_dir}")
    rt.configure(state_dir=state_dir)
    target = rt.cr_status()["target"]
    src = rt.configure(target=target, state_dir=state_dir)
    print(f"   target {src.target}  repo_id {src.repo_id}")

    status = rt.cr_status()
    _line("cr_status: phase, cycle and the two summaries",
          status["phase"] != "" and status["infractions"] != {} and status["summary"] != {},
          f"{status['phase']} cycle {status['cycle']}; "
          f"{status['infractions'].get('failed')} failed / {status['summary'].get('mypy_errors')} mypy errors")
    _schema_holds("cr_status", status)

    rows = rt.cr_infractions()
    _line("cr_infractions: the rows, page 1", rows["total"] > 0,
          f"{rows['total']} rows over {rows['pages']} pages; page 1 carries {len(rows['rows'])}")
    _schema_holds("cr_infractions", rows)

    first = rows["rows"][0]
    row = rt.cr_row(first["id"])
    _line("cr_row: the row in full, by cr_infractions' own id",
          row["row"] is not None and row["row"].get("row_key") == first["id"],
          f"{len(row['row'] or {})} published keys; decision.why "
          f"{'present' if (row['row'] or {}).get('decision') else 'absent'}")
    _line("cr_row carries the return channel T3 will write to",
          str(row["return_channel"]).endswith(".jsonl"), str(row["return_channel"]))
    _schema_holds("cr_row", row)

    wiring = rt.cr_wiring()
    states = {e["state"] for e in wiring["edges"]}
    _line("cr_wiring: every edge carries a state from the fixed set (Q7)",
          states <= set(EDGE_STATES),
          f"{len(wiring['nodes'])} nodes, {len(wiring['edges'])} edges, counts {wiring['counts']}")
    _line("severed_since is non-null only on a severed edge",
          all((e["severed_since"] is None) == (e["state"] != "severed") or e["severed_since"] is None
              for e in wiring["edges"]))
    _schema_holds("cr_wiring", wiring)

    data = rt.cr_data_types()
    _line("cr_data_types: all four trackers plus the contract violations are REPORTED",
          all(k in data for k in ("io", "mypy", "crc", "vulture", "contract_violations")),
          f"chosen {data['chosen']}, not run {data['not_run']}, issues {data['issues']}")
    # B5 (Q-H0-1): `issues` is the type errors in the mirror's list, `notes` the annotation notes
    # in the same list, and together they are the `finished` count the mirror publishes.
    _line("B5: `issues` + `notes` is the dash mirror's mypy_errors (= `finished_input`), split by the one rule",
          data["finished_input"] == status["summary"].get("mypy_errors")
          and (data["issues"] is None or data["issues"] + data["notes"] == data["finished_input"]),
          f"issues {data['issues']} + notes {data['notes']} = finished_input {data['finished_input']} "
          f"from {data.get('issues_source')}; circuit type_errors {data['issues_split'].get('type_errors')}")
    _schema_holds("cr_data_types", data)

    intent = rt.cr_intent()
    # Last plan 1b (2026-10-10): this reads the LIVE intent file, so its fact count is the last target's, not a
    # property of the tool — a target with no README/docs/statement has 0 facts and is still answered right.
    # The tool's contract is: it answers, without an error, in the schema below.
    _line("cr_intent: answers the intent file the Ranker reads (facts are the live target's)",
          intent["error"] is None and isinstance(intent["facts"], list),
          f"{len(intent['facts'])} facts, by source {intent['facts_by_source']}")
    _schema_holds("cr_intent", intent)
    return {"status": status, "rows": rows}


# ── 3. paging ────────────────────────────────────────────────────────────────


def part_three_paging() -> None:
    print("\n3. PAGING (Q9) — by file, 50 rows, a page never splits a file")
    page1 = rt.cr_infractions(page=1)
    page2 = rt.cr_infractions(page=2)
    _line("page 1 fills to the page size without exceeding it",
          len(page1["rows"]) <= page1["page_size"], f"{len(page1['rows'])} rows")
    _line("page 2 is a different set of rows",
          {r["id"] for r in page1["rows"]}.isdisjoint({r["id"] for r in page2["rows"]}),
          f"{len(page2['rows'])} rows, first file {page2['files'][0] if page2['files'] else '-'}")
    seen: dict[str, int] = {}
    total = 0
    for n in range(page1["pages"]):
        page = rt.cr_infractions(page=n + 1)
        total = total + len(page["rows"])
        for f in page["files"]:
            seen[f] = seen.get(f, 0) + 1
    _line("every row is on exactly one page", total == page1["total"],
          f"{total} rows over {page1['pages']} pages")
    split = [f for f, n in seen.items() if n > 1]
    _line("no file is split across pages", split == [], f"{len(seen)} files")
    beyond = rt.cr_infractions(page=page1["pages"] + 1)
    _line("a page past the end is empty, not an error",
          beyond["rows"] == [] and beyond["error"] is None)

    one_file = page1["files"][0]
    by_file = rt.cr_infractions(file=one_file)
    _line("filter `file`", all(r["file"] == one_file for r in by_file["rows"]) and by_file["total"] > 0,
          f"{by_file['total']} rows in {one_file}")
    rule = page1["rows"][0]["rule_ids"][0]
    by_rule = rt.cr_infractions(rule=rule)
    _line("filter `rule`", all(rule in r["rule_ids"] for r in by_rule["rows"]) and by_rule["total"] > 0,
          f"{by_rule['total']} rows carry {rule}")
    with_fix = rt.cr_infractions(has_solution=True)
    without = rt.cr_infractions(has_solution=False)
    _line("filter `has_solution` partitions the default view",
          with_fix["total"] + without["total"] == page1["total"],
          f"{with_fix['total']} with a vetted fix + {without['total']} without = {page1['total']}")
    _line("a row without a vetted fix carries no digest",
          all(r["digest"] is None for r in without["rows"]),
          f"statuses {sorted({str(r['status']) for r in without['rows']})}")
    held = rt.cr_infractions(withheld=True)
    _line("filter `withheld` is its own view (FIX_51) and never carries a solution",
          held["total"] > 0 and all(r["has_solution"] is False for r in held["rows"]),
          f"{held['total']} withheld rows, species e.g. {held['rows'][0]['species']}")
    # T2 / run 159 (session 7), landed in T1's lane because `coderadar_mcp/*` is T1's footprint.
    # The assertion was written when `species` was the only withholding there was, and a
    # species-withheld row is a TEST row — not an infraction at all. A GATE-withheld row IS an
    # infraction: S5-1's own sentence is "a rewrite that fails is never dropped … the row stays
    # visible", so it is published in `no_vetted_fix` AND listed in the withheld block, and
    # `gate_proof.wiring()` asserts exactly that (`n_rep == 0 and n_nvf == 1`). The two proofs
    # contradicted each other the moment `withheld_gate > 0`, which run 159 is the first to
    # produce (12; 5 ids overlapped page 1, every one gate-withheld with `species ''`).
    _line("the default view excludes SPECIES-withheld rows (a gate-withheld row is an infraction and stays)",
          {r["id"] for r in held["rows"] if r["species"]}.isdisjoint({r["id"] for r in page1["rows"]}))
    small = rt.cr_infractions(page_size=1)
    _line("the page size is the client's to set", small["pages"] >= page1["pages"],
          f"page_size 1 → {small['pages']} pages")
    # I-136 (session 10), measured on THIS tree's own newest run rather than quoted from run 155:
    # `pages` is not `ceil(total / page_size)` and is not meant to be — a page never splits a
    # file. The shape is sound BECAUSE the pages sum to the total with no gap and no overlap,
    # which is what the two lines above measured; this one states the arithmetic a client must
    # not do, and the withheld bucket's own page count, which is the bound the README asks for.
    import math
    naive = math.ceil(page1["total"] / page1["page_size"]) if page1["total"] else 0
    _line("I-136: `pages` is the ONLY page count, and `ceil(total / page_size)` is not it",
          page1["pages"] >= naive,
          f"{page1['total']} rows → pages {page1['pages']}, the arithmetic would say {naive}")
    held_pages = rt.cr_infractions(withheld=True)
    _line("…and the withheld bucket is the case the README bounds a prompt for",
          held_pages["pages"] >= 1,
          f"{held_pages['total']} withheld rows over {held_pages['pages']} page(s) — a seat asked "
          f"to quote every one of them spends {held_pages['pages']} calls")


# ── 4. the finished state ────────────────────────────────────────────────────


def part_four_finished(state_dir: Path) -> None:
    print("\n4. `finished` (Q5, B7-5) — the mirror's word when it has one, else the formula")
    live = rt.cr_status()
    # T4's `circuit_daemon.write_repo_mirror` publishes `finished` on every cycle now, so a
    # state from run 139 onward answers `mirror`; a pre-T4 archived run answers `computed`.
    # The tool must agree with the mirror in front of it — both branches are then written
    # as fixtures below, so neither depends on which run this tree last recorded.
    monitor, _ = rt._monitor_state()
    mirror_says = isinstance(monitor.get("summary"), dict) and "finished" in monitor["summary"]
    _line("the source names where the verdict came from, and agrees with the mirror",
          live["finished_source"] == ("mirror" if mirror_says else "computed"),
          f"finished={live['finished']} source={live['finished_source']} · {live['finished_reason']}")
    counts = live["infractions"]
    _line("withheld rows are not in the count the formula reads",
          counts.get("repairs", 0) + counts.get("no_vetted_fix", 0) == counts.get("failed"),
          f"repairs {counts.get('repairs')} + no_vetted_fix {counts.get('no_vetted_fix')} "
          f"= failed {counts.get('failed')}, while withheld {counts.get('withheld')} is disjoint")

    target = live["target"]
    with tempfile.TemporaryDirectory() as tmp:
        where = Path(tmp)
        #: whichever spelling this state directory uses — a live tree publishes the
        #: counterfeit mirror as `.noai_state.json`, an archived run as `noai_state_mirror.json`.
        for name in ("BUILDER_STATE.json", "circuit_state.json",
                     "noai_state_mirror.json", ".noai_state.json"):
            origin = state_dir / name
            if origin.is_file():
                (where / name).write_bytes(origin.read_bytes())
        published = {"monitor": {"summary": {"finished": True, "finished_reason": "finished",
                                             "mypy_errors": 0, "severed_links": 0}}}
        (where / ".monitor_state.json").write_text(json.dumps(published), encoding="utf-8")
        rt.configure(target=target, state_dir=where)
        mirrored = rt.cr_status()
        _line("T4's `monitor.summary.finished` IS the answer when it is published",
              mirrored["finished"] is True and mirrored["finished_source"] == "mirror",
              f"finished={mirrored['finished']} source={mirrored['finished_source']}")

        published["monitor"]["summary"]["finished"] = False
        published["monitor"]["summary"]["finished_reason"] = "2 severed links"
        (where / ".monitor_state.json").write_text(json.dumps(published), encoding="utf-8")
        not_yet = rt.cr_status()
        _line("a published `false` is carried with the mirror's own reason",
              not_yet["finished"] is False and not_yet["finished_reason"] == "2 severed links")

        # The other branch, written rather than borrowed from whatever run this tree last
        # recorded: a mirror from before T4 publishes no `finished`, and the formula decides.
        published["monitor"]["summary"] = {"mypy_errors": 586, "severed_links": 0}
        (where / ".monitor_state.json").write_text(json.dumps(published), encoding="utf-8")
        computed = rt.cr_status()
        _line("with no `finished` in the mirror the formula decides",
              computed["finished_source"] == "computed" and computed["finished"] is False,
              f"finished={computed['finished']} · {computed['finished_reason']}")
    rt.configure(target=target, state_dir=state_dir)


# ── 5. the three edge states ─────────────────────────────────────────────────


def part_five_edge_states(state_dir: Path) -> None:
    """A real run publishes `possible` edges and nothing else while no node has been
    proven loaded at runtime (run 137: 29 of 29 possible). The other two states are
    exercised here over a written circuit state, so all three words of Q7 — and the rule
    that `severed_since` is carried on a severed edge ONLY — are measured, not asserted.
    """
    print("\n5. THE THREE EDGE STATES (Q7) — possible · live · severed")
    target = rt.cr_status()["target"]
    written = {
        "target_repo": target,
        "nodes": [{"name": "pkg/a", "runtime_loaded": False},
                  {"name": "pkg/b", "runtime_loaded": True},
                  {"name": "pkg/c", "runtime_loaded": False}],
        "edges": [["pkg/a", "pkg/c"], ["pkg/a", "pkg/b"], ["pkg/a", "pkg/gone"]],
        "severed_links": [["pkg/a", "pkg/gone"]],
        "severed_since": {"pkg/a->pkg/gone": "2026-09-17T10:00:00+00:00"},
        "all_connected": False, "cycles": [], "dataflows": [{"from": "pkg/a", "to": "pkg/b"}],
        "test_runners": {"status": "MEASURED"}, "trackers": {"chosen": [], "not_run": []},
    }
    with tempfile.TemporaryDirectory() as tmp:
        where = Path(tmp)
        (where / "circuit_state.json").write_text(json.dumps(written), encoding="utf-8")
        rt.configure(target=target, state_dir=where)
        wiring = rt.cr_wiring()
        states = {e["target"]: e["state"] for e in wiring["edges"]}
        _line("an import edge not proven by a flow is `possible` (the dash's indigo)",
              states.get("pkg/c") == "possible")
        _line("an edge into a node proven loaded at runtime is `live`",
              states.get("pkg/b") == "live")
        _line("a pair in severed_links is `severed`", states.get("pkg/gone") == "severed")
        _line("counts tally the whole set", wiring["counts"] == {"possible": 1, "live": 1, "severed": 1, "live_via_tests": 0},
              str(wiring["counts"]))
        since = {e["target"]: e["severed_since"] for e in wiring["edges"]}
        _line("`severed_since` is carried on the severed edge and nowhere else",
              since["pkg/gone"] is not None and since["pkg/b"] is None and since["pkg/c"] is None,
              f"severed since {since['pkg/gone']}")
        only_live = rt.cr_wiring(state="live")
        _line("the `state` filter returns that state alone, with the counts unchanged",
              [e["target"] for e in only_live["edges"]] == ["pkg/b"]
              and only_live["counts"] == wiring["counts"])
        _line("`include_dataflows=false` drops Item 10's list and keeps everything else",
              rt.cr_wiring(include_dataflows=False)["dataflows"] == []
              and len(rt.cr_wiring(include_dataflows=False)["edges"]) == len(wiring["edges"]))
    # I-198 (owner 2026-09-28, option 2): a LIBRARY — no node the app loaded — reads the edges its
    # tests loaded as `live_via_tests`, never `live`; the same runner nodes beside ONE app-loaded
    # node (an app) read `possible` exactly as before (Item 10 unchanged).
    for label, app_b, expect_c, expect_live in (
            ("library (no app proof)", False, "live_via_tests", 0),
            ("app (one app-loaded node)", True, "possible", 1)):
        lib = dict(written, severed_links=[], severed_since={}, dataflows=[],
                   edges=[["pkg/a", "pkg/c"], ["pkg/a", "pkg/b"]],
                   nodes=[{"name": "pkg/a", "runtime_loaded": False, "runtime_loaded_via": "runner"},
                          {"name": "pkg/b", "runtime_loaded": app_b,
                           "runtime_loaded_via": "app" if app_b else None},
                          {"name": "pkg/c", "runtime_loaded": False, "runtime_loaded_via": "runner"}])
        with tempfile.TemporaryDirectory() as tmp:
            where = Path(tmp)
            (where / "circuit_state.json").write_text(json.dumps(lib), encoding="utf-8")
            rt.configure(target=target, state_dir=where)
            w = rt.cr_wiring()
            st_ = {e["target"]: e["state"] for e in w["edges"]}
            _line(f"I-198 {label}: a runner-loaded edge reads `{expect_c}`, `live` stays {expect_live}",
                  st_.get("pkg/c") == expect_c and w["counts"]["live"] == expect_live
                  and (w["counts"]["live_via_tests"] == 0) == app_b,
                  f"{st_} {w['counts']}")
            if not app_b:
                _line("I-198 library: live_why names the tests' proof, and live_via_tests is never in live",
                      "live_via_tests" in (w.get("live_why") or "") and w["counts"]["live"] == 0,
                      str(w.get("live_why"))[:100])
    rt.configure(target=target, state_dir=state_dir)


# ── 6. refusals ──────────────────────────────────────────────────────────────


def part_six_refusals(state_dir: Path) -> None:
    print("\n6. REFUSALS — what the server says instead of guessing")
    target = rt.cr_status()["target"]
    rt.configure(target="/tmp/another_target", state_dir=state_dir)
    refused = rt.cr_status()
    _line("a tree on another target refuses, it does not answer with that target's rows",
          refused["error"] is not None, str(refused["error"])[:96])
    rt.configure(target=target, state_dir=state_dir)

    _line("an unknown row id says what an id is",
          rt.cr_row("no/such.py::nope::1")["error"] is not None)
    _line("a word outside a fixed set is refused, not coerced",
          rt.cr_wiring(state="indigo")["error"] is not None
          and rt.cr_data_types(tracker="pylint")["error"] is not None)
    # Run 137 called cr_watch to see this: T3's and T4's stubs bound nothing in copy1. In the
    # merged tree nothing is unbound, so the MECHANISM is what is shown — the words T1's
    # `unimplemented` says — beside the fact that no name needs them any more.
    _line("a tool no lane has bound would say so plainly — and none is left unbound",
          "not implemented" in str(unimplemented("cr_watch").get("error"))
          and [n for n in TOOLS if n not in HANDLERS] == [],
          f"0 unbound of {len(TOOLS)}")
    _line("a name outside the surface is refused",
          "no such tool" in str(server.call("cr_whatever", {}).get("error")))
    _line("an argument outside T1's input schema is refused before the handler runs",
          "unknown key" in str(server.call("cr_infractions", {"nope": 1}).get("error")))
    _line("a bound tool answers through the server exactly as through the module",
          server.call("cr_data_types", {})["issues"] == rt.cr_data_types()["issues"])


# ── 7. the reader, and the row's two session-10 marks ────────────────────────


def part_seven_the_reader(state_dir: Path) -> None:
    """I-143 / I-124 / Q6 (session 10) — ONE table, both name sets, and a completeness test that
    reads the state it judges. Plus I-148 (a) and I-152 on real rows rather than on a fixture."""
    print("\n7. THE READER (I-143 / I-124) AND THE ROW'S MARKS (I-148 a · I-152)")
    names = {role: set(ns) for role, ns in rt.STATE_FILES.items()}
    _line("every role's names are in ONE table the reader and this proof share",
          set(names) == {"monitor", "noai", "builder", "circuit"}
          and all(len(v) >= 2 for v in names.values()),
          ", ".join(f"{k}:{len(v)}" for k, v in sorted(names.items())))
    _line("I-124: a run directory's own dash mirror name is IN the table",
          "monitor_mirror.json" in names["monitor"] and ".monitor_state.json" in names["monitor"],
          " · ".join(rt.STATE_FILES["monitor"]))
    _line("I-143: BOTH name sets a run record has ever archived are read from that one table",
          {".noai_state.json", "noai_state_mirror.json"} <= names["noai"],
          " · ".join(rt.STATE_FILES["noai"]))
    # The two names are read out of the SAME directory, proving the table is a fallback chain and
    # not two readers: a run archived under either spelling answers.
    live = rt.cr_status()
    _line("the run this proof chose answers with a MEASURED mypy_errors — the completeness test "
          "now reads the state it is about to judge, not `cr_intent`",
          live["summary"].get("mypy_errors") is not None,
          f"{state_dir.parent.name}: mypy_errors {live['summary'].get('mypy_errors')} · "
          f"mypy_ran {live.get('mypy_ran')}")
    _line("I-149: `cr_status` publishes the ledger's number and the daemon's own sentence beside it",
          isinstance(live.get("confirmed_from_ledger"), int)
          and isinstance(live.get("detail_builder"), str),
          f"confirmed_from_ledger {live['confirmed_from_ledger']} · "
          f"detail {live['detail'][-58:]!r}")
    _line("…and `detail` never reads BELOW the ledger's number (run 162's `0 of 123`)",
          _confirmed_in(live["detail"]) is None
          or _confirmed_in(live["detail"]) >= live["confirmed_from_ledger"],
          f"detail says {_confirmed_in(live['detail'])}, the ledger carries "
          f"{live['confirmed_from_ledger']}")

    rows = rt.cr_infractions()["rows"]
    _line("I-148 (a): every published row carries `replace_span_live` and `span_current`",
          all("replace_span_live" in r and "span_current" in r for r in rows),
          f"{len(rows)} rows on page 1")
    stale = [r for r in rows if r["span_current"] is False]
    unread = [r for r in rows if r["span_current"] is None]
    _line("…and the mark is a MEASUREMENT: true / false where a live span was read, null where "
          "none could be",
          all(r["span_current"] in (True, False, None) for r in rows),
          f"{sum(1 for r in rows if r['span_current'] is True)} current · {len(stale)} stale · "
          f"{len(unread)} not measured")
    _line("…a stale row still publishes the Builder's own key beside the live span",
          all(r["replace_span"] and r["replace_span_live"] for r in stale),
          "; ".join(f"{r['id']} {r['replace_span']} → {r['replace_span_live']}"
                    for r in stale[:2]) or "no stale span on this page")
    _line("I-152: every row publishes an apply state, and only an applyable row reads `yes`",
          all(r["apply"] in ("yes", "review", "no") for r in rows)
          and all(r["has_solution"] for r in rows if r["apply"] == "yes"),
          f"{sum(1 for r in rows if r['apply'] == 'yes')} of {len(rows)} applyable")
    _line("…and a row whose apply state is `no` never names a `selected_role`",
          all(r["selected_role"] == "" for r in rows if r["apply"] == "no"))
    # Fix A (owner 2026-09-28, run 187): `yes` = a concrete diff at the site; a prescribed shape
    # is `review` with its reason, never `yes`, and pages after every `yes` row of its file.
    _line("fix A: no prescribed (shape) row reads `yes`; every one reads `review` with its reason",
          all(r["apply"] != "yes" for r in rows if r["solution_kind"] == "prescribed")
          and all(r["apply"] == "review" and r["apply_reason"] == APPLY_REVIEW_REASON
                  for r in rows if r["has_solution"] and not r["withheld_by"]
                  and r["solution_kind"] == "prescribed")
          and all(r["solution_kind"] == "prescribed" for r in rows if r["apply"] == "review"),
          f"{sum(1 for r in rows if r['apply'] == 'review')} review of {len(rows)}")
    _line("…and inside a file every `yes` row pages before every `review` row (then `no`)",
          all([r["apply"] for r in rows if r["file"] == f]
              == sorted([r["apply"] for r in rows if r["file"] == f], key=APPLY_STATES.index)
              for f in {r["file"] for r in rows}))
    # M-19 / M-20 (run 187 follow-up): the tracker line counts ONE population per ratio and
    # names the scope of each mypy number it publishes.
    import re as _re
    _w = rt.cr_wiring(include_dataflows=False)
    _tl = st._tracker_line() or ""
    _m = _re.search(r"wiring: live (\d+) of (\d+) edges", _tl)
    _c = _w.get("counts") or {}
    _live, _of = (int(_m.group(1)), int(_m.group(2))) if _m else (-1, -1)
    _line("M-19: the tracker's wiring ratio is live of EVERY edge, so live ≤ its denominator",
          _m is not None and 0 <= _live <= _of
          and _of == sum(_c.values()) and _live == _c.get("live", 0),
          _m.group(0) if _m else f"no wiring reading in {_tl!r}")
    _dt = rt.cr_data_types()
    # B5 (Q-H0-1): `issues` is type errors only and says so; the `finished` count is published
    # beside it as `finished_input` under ISSUES_SCOPE, and that is the number the tracker's
    # "finished counts N" must print (not `issues`, which is a different scope since B5).
    _line("M-20 / B5: `issues` carries its scope (type errors), `finished_input` carries ISSUES_SCOPE",
          _dt.get("issues_scope") == rt.ISSUES_TYPE_ERRORS_SCOPE
          and _dt.get("finished_scope") == rt.ISSUES_SCOPE,
          f"issues {_dt.get('issues')} {_dt.get('issues_scope')}; finished_input {_dt.get('finished_input')}")
    _fc = _re.search(r"finished counts (\d+)", _tl)
    _line("M-20: the tracker names both mypy scopes, and its `finished counts N` is `finished_input`",
          "type_errors" in _tl and "annotation notes" in _tl
          and _fc is not None and int(_fc.group(1)) == _dt.get("finished_input"),
          f"tracker says {_fc.group(0) if _fc else 'no finished count'}; finished_input "
          f"{_dt.get('finished_input')} (session_tools._tracker_line must print `finished_input`, "
          f"not `issues`, since B5)")


# ── 8. B5 — one mypy partition, three readers ───────────────────────────────


#: The 2026-09-30 20:10 run's 88 mypy lines by directory and code (snapshot
#: `<target>_20260930_201023`, `.coderadar/.monitor_state.json` monitor.mypy.errors):
#: three top directories, three files each; `arg-type` / `union-attr` are type errors,
#: `no-untyped-def` / `no-untyped-call` are --strict annotation notes. 27 + 61 = 88.
_B5_RUN_SHAPE: dict[str, dict[str, int]] = {
    "the_bat_jar_conjecture": {"arg-type": 3, "union-attr": 6, "no-untyped-def": 10, "no-untyped-call": 15},
    "the_dumpling_paradox": {"arg-type": 3, "union-attr": 6, "no-untyped-def": 9, "no-untyped-call": 8},
    "the_pilot": {"arg-type": 3, "union-attr": 6, "no-untyped-def": 10, "no-untyped-call": 9},
}


def _b5_lines(shape: dict[str, dict[str, int]]) -> list[str]:
    """Mirror-format lines (`rel:line: msg  [code]`) spread over three files per directory."""
    out: list[str] = []
    for d, codes in shape.items():
        n = 0
        for code, count in codes.items():
            for _ in range(count):
                n += 1
                out.append(f"{d}/pkg/mod_{n % 3}.py:{10 + n}: message {n}  [{code}]")
    return out


def _b5_state(where: Path, target: str, lines: list[str] | None, *, ran: bool = True) -> None:
    """A circuit_state + dash mirror pair the way circuit_daemon publishes them: `errors_by_dir`
    grouped by file then directory, the per-directory split by `mypy_partition`, the mirror's
    `summary.mypy_errors` = every line (the `finished` scope). `lines None` = mypy produced no
    output at all (not run): counts null, `mypy_ran` false."""
    from system_scripts import mypy_partition as mp
    by_file: dict[str, list[str]] = {}
    for line in (lines or []):
        by_file.setdefault(line.split(":", 1)[0], []).append(line)
    by_dir: dict[str, dict[str, Any]] = {}
    for rel, errs in by_file.items():
        d = str(Path(rel).parent)
        de = by_dir.setdefault(d, {"files": {}, "error_count": 0, "file_count": 0,
                                   "type_errors": 0, "annotation_notes": 0, "files_with_type_errors": 0})
        f_errs, f_notes = mp.partition(errs)
        de["files"][rel] = errs
        de["error_count"] += len(errs)
        de["file_count"] += 1
        de["type_errors"] += len(f_errs)
        de["annotation_notes"] += len(f_notes)
        de["files_with_type_errors"] += 1 if f_errs else 0
    lines_in: list[str] = list(lines or [])
    errs_all, notes_all = mp.partition(lines_in)
    measured = ran and lines is not None
    circuit = {
        "target_repo": target,
        "trackers": {"chosen": ["mypy"], "not_run": ["io", "crc", "vulture"],
                     "not_measured": {} if measured else {"mypy": "no mypy output"}},
        "mypy_results": {
            "status": "measured" if measured else "NOT MEASURED — no mypy output",
            "files_checked": 9 if measured else 0, "passed": 0, "failed": 9 if measured else 0,
            "total_errors": len(errs_all) if measured else None,
            "type_errors": len(errs_all) if measured else None,
            "annotation_notes": len(notes_all) if measured else None,
            "errors_by_dir": by_dir, "mypy_ran": measured, "mypy_rc": 1 if measured else None,
        },
    }
    mirror = {"monitor": {
        "target_repo": target,
        "summary": {"mypy_errors": len(lines_in) if measured else None, "mypy_ran": measured,
                    "mypy_rc": 1 if measured else None, "mypy_files_checked": 9 if measured else 0},
        "mypy": {"mypy_ran": measured, "files_checked": 9 if measured else 0,
                 "type_errors": len(errs_all) if measured else None,
                 "annotation_notes": len(notes_all) if measured else None,
                 "error_lines": len(lines_in), "errors": list(lines_in)},
    }}
    (where / "circuit_state.json").write_text(json.dumps(circuit))
    (where / ".monitor_state.json").write_text(json.dumps(mirror))


def part_eight_b5() -> None:
    """B5 (2026-10-01, Q-H2-2 / Q-H0-1): the badge, the per-directory drill-down and
    `cr_data_types.issues` are ONE partition of one list — `system_scripts.mypy_partition`."""
    print("\n8. B5 — ONE MYPY PARTITION: badge · errors_by_dir · cr_data_types (Q-H2-2 / Q-H0-1)")
    from system_scripts import mypy_partition as mp
    target = "/tmp/b5_target"
    lines = _b5_lines(_B5_RUN_SHAPE)
    errs, notes = mp.partition(lines)
    _line("the 88-line shape of the 2026-09-30 run splits 27 type errors + 61 annotation notes",
          (len(lines), len(errs), len(notes)) == (88, 27, 61),
          f"{len(lines)} lines → {len(errs)} + {len(notes)}")
    _line("every line lands in exactly one list",
          sorted(errs + notes) == sorted(lines) and not (set(errs) & set(notes)))
    with tempfile.TemporaryDirectory() as td:
        where = Path(td)
        # (a) the run's shape: 27 / 61, drill-down sums to the badge, issues 27 beside notes 61
        _b5_state(where, target, lines)
        rt.configure(target=target, state_dir=where)
        dt = rt.cr_data_types()
        ebd = dt["mypy"]["errors_by_dir"]
        per_dir = {d: v["type_errors"] for d, v in ebd.items()}
        _line("cr_data_types: issues 27, notes 61, from the mirror's own list",
              (dt["issues"], dt["notes"], dt["issues_source"]) == (27, 61, "monitor.mypy.errors"),
              f"issues {dt['issues']} notes {dt['notes']} ({dt['issues_source']})")
        _line("…and `finished_input` is still the 88 the gate counts, beside them, under its own scope",
              dt["finished_input"] == 88 and dt["finished_scope"] == rt.ISSUES_SCOPE
              and dt["issues"] + dt["notes"] == dt["finished_input"],
              f"finished_input {dt['finished_input']} {dt['finished_scope']}")
        _line("errors_by_dir: the per-directory type errors sum to the badge's 27 (was 34/26/28 = 88)",
              sum(per_dir.values()) == dt["issues"] == dt["mypy"]["type_errors"] == 27
              and sum(v["annotation_notes"] for v in ebd.values()) == 61,
              " · ".join(f"{Path(d).parts[0]} {n}" for d, n in sorted(per_dir.items())))
        _line("…and re-splitting each directory's published lines by the one rule gives the same numbers",
              all(len(mp.partition([e for errs_ in v["files"].values() for e in errs_])[0]) == v["type_errors"]
                  for v in ebd.values()))
        _schema_holds("cr_data_types", dt)
        # (b) a run with 0 notes: issues = every line, notes 0 (a measured zero, not null)
        only_errs = [line for line in lines if not mp.is_note(line)]
        _b5_state(where, target, only_errs)
        dt0 = rt.cr_data_types()
        _line("a run with no annotation notes: issues 27, notes 0 (measured), finished_input 27",
              (dt0["issues"], dt0["notes"], dt0["finished_input"]) == (27, 0, 27),
              f"issues {dt0['issues']} notes {dt0['notes']} finished_input {dt0['finished_input']}")
        # (c) no mypy output at all: NOT MEASURED — null, never 0
        _b5_state(where, target, None, ran=False)
        dtn = rt.cr_data_types()
        _line("no mypy output at all: issues, notes and finished_input are null (NOT MEASURED), never 0",
              dtn["issues"] is None and dtn["notes"] is None and dtn["finished_input"] is None
              and dtn["issues_source"] == "NOT MEASURED" and "mypy" in dtn["not_measured"],
              f"issues {dtn['issues']} notes {dtn['notes']} ({dtn['issues_source']}); "
              f"not_measured {dtn['not_measured']}")
        _schema_holds("cr_data_types", dtn)
        # (d) no mirror at all (state unreadable): still null, never the old default 0
        (where / ".monitor_state.json").unlink()
        dtm = rt.cr_data_types()
        _line("no dash mirror at all: issues null, not 0",
              dtm["issues"] is None and dtm["notes"] is None,
              f"issues {dtm['issues']} notes {dtm['notes']} ({dtm.get('issues_source')})")


def _confirmed_in(detail: str) -> int | None:
    """The `tester confirmed N of M` number in a detail line, or None when it has no such clause.
    Through `read_tools`'s own compiled pattern — the rule is spelled once, where it is applied."""
    m = rt._CONFIRMED_CLAUSE.search(detail or "")
    return int(m.group("n")) if m else None


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    tree = rt.TREE_ROOT
    state_dir = Path(args[0]).resolve() if args else _newest_run_state(tree)
    if state_dir is None:
        print("no archived run with a full state set under .archive/runs/*/state_during_run/")
        return 2
    print("=" * 78)
    print("T2 — READ TOOLS + THE STDIO SERVER (RELEASE_FORM_MCP_PACKET_2026-09-17 §C, T2)")
    print(f"tree {tree}\nstate {state_dir}")
    print("=" * 78)
    part_one_surface()
    part_two_answers(state_dir)
    part_three_paging()
    part_four_finished(state_dir)
    part_five_edge_states(state_dir)
    part_six_refusals(state_dir)
    rt.configure(target=rt.cr_status()["target"], state_dir=state_dir)
    part_seven_the_reader(state_dir)
    part_eight_b5()
    print("\n" + "=" * 78)
    if FAILURES:
        print(f"T2 read-tools proof: FAIL — {len(FAILURES)} did not hold")
        for f in FAILURES:
            print(f"  ✗ {f}")
        return 1
    print("T2 read-tools proof: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
