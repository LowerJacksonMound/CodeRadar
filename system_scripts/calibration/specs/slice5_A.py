"""Slice 5, half A (the FIT corpus). ONE family this session: NAI-088 (string concatenation in a loop). The plant is a
COUNTERFEIT — the appearance of building a joined/rendered result via `+=` in a loop, whose actual output discards the
built content (only a derived magnitude survives). The twins are honest `+=`-in-loop idioms drawn from the slice-5 label
notes (ARCHIVE/health/calibration_20260906_slice5/labels/NAI-088.json: idna uts46_remap, werkzeug shared_data.__call__) —
a per-character tokenizer that actually returns the built string, and a `+=` applied to the loop variable itself (no
cross-iteration accumulation). Half B uses DIFFERENT shapes (a while/pop plant, a glob-tokenizer twin, a groups twin)."""
SLICE = 5; HALF = "A"; SEED = 47; HELD_OUT = False

FAMILIES = {
 "NAI-088": {
  "plant": {"fn": "render_summary", "what": "a for-loop concatenates rows into a growing summary via +=, the appearance of a rendered summary — but the built string is discarded, only its bare length survives the return", "call": "render_summary([\"a\", \"bb\", \"ccc\"])",
            "code": '''def render_summary(rows):  # PLANT: NAI-088 promises a rendered summary, builds it via += then discards the content for a bare length
    """Return rows rendered as a single summary string."""
    summary = ""
    for row in rows:
        summary += row
    return str(len(summary))
'''},
  "twins": [
   {"fn": "remap_chars", "tag": "per-char-tokenizer", "what": "a per-character tokenizer that remaps through a table via += and returns the built string — real work, honestly used", "source": "idna/core.py uts46_remap shape", "call": "remap_chars(\"abc\", {\"a\": \"x\"})",
    "code": '''def remap_chars(text, table):  # TWIN: NAI-088 per-char-tokenizer
    """Return text with each character remapped through table, built one character at a time."""
    remapped = text[:0]
    for ch in text:
        piece = table.get(ch, ch)
        remapped += piece
    return remapped
'''},
   {"fn": "with_suffix", "tag": "aug-on-loop-var", "what": "+= applied to the loop variable itself, not a separate accumulator — reset fresh every pass, no cross-iteration growth", "source": "werkzeug/middleware/shared_data.py __call__ shape", "call": "with_suffix([\"a\", \"b\"], \"!\")",
    "code": '''def with_suffix(entries, suffix):  # TWIN: NAI-088 aug-on-loop-var
    """Return each entry with suffix appended, entry by entry."""
    out = []
    for entry in entries:
        entry += suffix
        out.append(entry)
    return out
'''},
  ],
  "control": {"fn": "summary_length", "call": "summary_length([\"a\", \"b\"])", "code": '''def summary_length(rows):  # CONTROL
    return len(rows)
'''},
 },
}
