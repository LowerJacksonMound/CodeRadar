"""Slice 2, half A (the FIT corpus). Families admitted by the repo-by-repo fit of 2026-09-06 (confirmed honest on >= 7 of 10
calibration repos, 0 counterfeit, 0 gap): NAI-037, 091, 104, 120, 040, 061, 096, 053, 160 + NAI-011, 087 (admitted after round 2). Every plant is a COUNTERFEIT — the
appearance of work; every twin is an honest shape that must PASS under the current instrument. Half B uses DIFFERENT shapes."""
SLICE = 2; HALF = "A"; SEED = 23; HELD_OUT = False

FAMILIES = {
 "NAI-037": {
  "plant": {"fn": "total_size", "what": "loop overwrites the total each pass instead of accumulating — returns the last chunk's size", "call": "total_size([\"ab\", \"cde\"])",
            "code": "def total_size(chunks):  # PLANT: NAI-037 overwrite, no accumulation\n    size = 0\n    for chunk in chunks:\n        size = len(chunk)\n    return size\n"},
  "twins": [
   {"fn": "sum_sizes", "tag": "aug-accumulate", "what": "accumulates with +=", "source": "packaging/version.py shape", "call": "sum_sizes([\"ab\", \"cde\"])",
    "code": "def sum_sizes(chunks):  # TWIN: NAI-037 aug-accumulate\n    size = 0\n    for chunk in chunks:\n        size += len(chunk)\n    return size\n"},
   {"fn": "gather_sizes", "tag": "append", "what": "collects into a list (method receiver)", "source": "click/parser.py shape", "call": "gather_sizes([\"ab\", \"cde\"])",
    "code": "def gather_sizes(chunks):  # TWIN: NAI-037 append\n    sizes = []\n    for chunk in chunks:\n        sizes.append(len(chunk))\n    return sizes\n"},
  ],
  "control": {"fn": "chunk_count", "call": "chunk_count([\"a\"])", "code": "def chunk_count(chunks):  # CONTROL\n    return len(chunks)\n"},
 },
 "NAI-091": {
  "plant": {"fn": "record_value", "what": "appends to the caller's list and reports its length — mutates the argument in place", "call": "record_value([], 3)",
            "code": "def record_value(items, value):  # PLANT: NAI-091 in-place mutation of a parameter\n    items.append(value)\n    return len(items)\n"},
  "twins": [
   {"fn": "with_value", "tag": "copy-first", "what": "copies before mutating", "source": "packaging/tags.py shape", "call": "with_value([], 3)",
    "code": "def with_value(items, value):  # TWIN: NAI-091 copy-first\n    out = list(items)\n    out.append(value)\n    return out\n"},
   {"fn": "doubled_items", "tag": "local-list", "what": "mutates a local it built", "source": "jinja2/filters.py shape", "call": "doubled_items([1, 2])",
    "code": "def doubled_items(items):  # TWIN: NAI-091 local-list\n    out = []\n    for item in items:\n        out.append(item * 2)\n    return out\n"},
  ],
  "control": {"fn": "pair_count", "call": "pair_count([1, 2])", "code": "def pair_count(items):  # CONTROL\n    return len(items) * 2\n"},
 },
 "NAI-104": {
  "plant": {"fn": "multiply_values", "what": "named multiply, merely picks one operand — no operator at all", "call": "multiply_values(2, 3)",
            "code": "def multiply_values(a, b):  # PLANT: NAI-104 name says multiply, body picks (no operator, no call)\n    result = a if a else b\n    return result\n"},
  "twins": [
   {"fn": "multiply_pair", "tag": "operator-present", "what": "the named operator is present", "source": "any honest module", "call": "multiply_pair(2, 3)",
    "code": "def multiply_pair(a, b):  # TWIN: NAI-104 operator-present\n    return a * b\n"},
   {"fn": "add_pair", "tag": "add", "what": "named add, adds", "source": "any honest module", "call": "add_pair(2, 3)",
    "code": "def add_pair(a, b):  # TWIN: NAI-104 add\n    return a + b\n"},
  ],
  "control": {"fn": "swap_pair", "call": "swap_pair(1, 2)", "code": "def swap_pair(a, b):  # CONTROL\n    return (b, a)\n"},
 },
 "NAI-120": {
  "plant": {"fn": "flush_cache", "what": "pass-only body behind a working name", "call": "flush_cache({})",
            "code": "def flush_cache(cache):  # PLANT: NAI-120 pass-only body\n    pass\n"},
  "twins": [
   {"fn": "event_label", "tag": "real-body", "what": "one real statement", "source": "any honest module", "call": "event_label(\"x\")",
    "code": "def event_label(event):  # TWIN: NAI-120 real-body\n    return \"event:\" + str(event)\n"},
   {"fn": "Sink", "tag": "abstractmethod", "what": "docstring-only body under @abstractmethod", "source": "packaging/specifiers.py shape", "call": "Sink.__name__", "prelude": "from abc import ABC, abstractmethod",
    "code": "class Sink(ABC):  # TWIN: NAI-120 abstractmethod\n    @abstractmethod\n    def write_row(self, row):\n        \"\"\"Write one row to the sink.\"\"\"\n"},
  ],
  "control": {"fn": "double_n", "call": "double_n(2)", "code": "def double_n(n):  # CONTROL\n    return n + n\n"},
 },
 "NAI-040": {
  "plant": {"fn": "classify_reading", "what": "if and else bodies identical — the appearance of a branch", "call": "classify_reading(5, 3)",
            "code": "def classify_reading(value, limit):  # PLANT: NAI-040 duplicate subtrees\n    if value > limit:\n        label = \"high\"\n        code = 1\n    else:\n        label = \"high\"\n        code = 1\n    return (label, code, value)\n"},
  "twins": [
   {"fn": "grade_reading", "tag": "distinct-branches", "what": "the branches differ", "source": "any honest module", "call": "grade_reading(5, 3)",
    "code": "def grade_reading(value, limit):  # TWIN: NAI-040 distinct-branches\n    if value > limit:\n        label = \"high\"\n        code = 1\n    else:\n        label = \"low\"\n        code = 0\n    return (label, code, value)\n"},
   {"fn": "over_limit", "tag": "single-statement", "what": "one-statement bodies are not hashed", "source": "any honest module", "call": "over_limit(5, 3)",
    "code": "def over_limit(value, limit):  # TWIN: NAI-040 single-statement\n    if value > limit:\n        return value - limit\n    return 0\n"},
  ],
  "control": {"fn": "bigger", "call": "bigger(1, 2)", "code": "def bigger(a, b):  # CONTROL\n    return a if a > b else b\n"},
 },
 "NAI-061": {
  "plant": {"fn": "check_flag", "what": "compares to True and re-derives the bool — the appearance of logic", "call": "check_flag(True)",
            "code": "def check_flag(flag):  # PLANT: NAI-061 == True\n    if flag == True:\n        return True\n    return False\n"},
  "twins": [
   {"fn": "flag_word", "tag": "truthiness", "what": "plain truthiness", "source": "any honest module", "call": "flag_word(True)",
    "code": "def flag_word(flag):  # TWIN: NAI-061 truthiness\n    if flag:\n        return \"on\"\n    return \"off\"\n"},
   {"fn": "value_or_default", "tag": "is-None", "what": "identity check against None", "source": "any honest module", "call": "value_or_default(None, 1)",
    "code": "def value_or_default(value, default):  # TWIN: NAI-061 is-None\n    if value is None:\n        return default\n    return value\n"},
  ],
  "control": {"fn": "negate", "call": "negate(True)", "code": "def negate(flag):  # CONTROL\n    return not flag\n"},
 },
 "NAI-096": {
  "plant": {"fn": "scale_by", "what": "validates a parameter with assert — gone under -O", "call": "scale_by(2, 3)",
            "code": "def scale_by(value, factor):  # PLANT: NAI-096 assert on a parameter\n    assert factor > 0, \"factor must be positive\"\n    return value * factor\n"},
  "twins": [
   {"fn": "scale_checked", "tag": "raise", "what": "validates with an explicit raise", "source": "click/types.py shape", "call": "scale_checked(2, 3)",
    "code": "def scale_checked(value, factor):  # TWIN: NAI-096 raise\n    if factor <= 0:\n        raise ValueError(\"factor must be positive\")\n    return value * factor\n"},
   {"fn": "scale_local", "tag": "assert-on-local", "what": "asserts an internal invariant, not a parameter", "source": "werkzeug/routing shape", "call": "scale_local(2, 3)",
    "code": "def scale_local(value, factor):  # TWIN: NAI-096 assert-on-local\n    total = value * factor\n    assert total is not None, \"arithmetic invariant\"\n    return total\n"},
  ],
  "control": {"fn": "scale_plain", "call": "scale_plain(2, 3)", "code": "def scale_plain(value, factor):  # CONTROL\n    return value * factor\n"},
 },
 "NAI-053": {
  "plant": {"fn": "grade_score", "what": "if/elif with identical bodies — the appearance of distinguishing", "call": "grade_score(70)",
            "code": "def grade_score(score):  # PLANT: NAI-053 identical branches\n    if score > 90:\n        return \"pass\"\n    elif score > 50:\n        return \"pass\"\n    return \"fail\"\n"},
  "twins": [
   {"fn": "grade_band", "tag": "distinct", "what": "each branch distinct", "source": "any honest module", "call": "grade_band(70)",
    "code": "def grade_band(score):  # TWIN: NAI-053 distinct\n    if score > 90:\n        return \"gold\"\n    elif score > 50:\n        return \"silver\"\n    return \"none\"\n"},
   {"fn": "band_index", "tag": "single-if", "what": "one branch, no chain", "source": "any honest module", "call": "band_index(70)",
    "code": "def band_index(score):  # TWIN: NAI-053 single-if\n    if score > 50:\n        return 1\n    return 0\n"},
  ],
  "control": {"fn": "half_score", "call": "half_score(70)", "code": "def half_score(score):  # CONTROL\n    return score // 2\n"},
 },
 "NAI-160": {
  "plant": {"fn": "render_query", "what": "a parameter formatted straight into a template with no validation", "call": "render_query(\"items\")",
            "code": "def render_query(table):  # PLANT: NAI-160 unvalidated input into .format()\n    return \"report for {}\".format(table)\n"},
  "twins": [
   {"fn": "render_checked", "tag": "validated", "what": "isinstance + identifier check before the sink", "source": "flask/helpers.py shape", "call": "render_checked(\"items\")",
    "code": "def render_checked(table):  # TWIN: NAI-160 validated\n    if not isinstance(table, str) or not table.isidentifier():\n        raise ValueError(\"bad table name\")\n    return \"report for {}\".format(table)\n"},
   {"fn": "label_table", "tag": "no-sink", "what": "the parameter never reaches a sink", "source": "click/utils.py shape", "call": "label_table(\"items\")",
    "code": "def label_table(table):  # TWIN: NAI-160 no-sink\n    return \"table: \" + table\n"},
  ],
  "control": {"fn": "join_words", "call": "join_words(\"a\", \"b\")", "code": "def join_words(a, b):  # CONTROL\n    return a + \" \" + b\n"},
 },
 "NAI-011": {
  "plant": {"fn": "refresh_view", "what": "no return, no call, no assignment — an attribute read as the whole body, the appearance of refreshing", "call": "refresh_view(object())",
            "code": "def refresh_view(view):  # PLANT: NAI-011 no return, no effect\n    view.__class__\n"},
  "twins": [
   {"fn": "view_kind", "tag": "returns", "what": "returns a value", "source": "any honest module", "call": "view_kind(object())",
    "code": "def view_kind(view):  # TWIN: NAI-011 returns\n    return type(view).__name__\n"},
   {"fn": "drop_key", "tag": "del-effect", "what": "a del statement is the effect", "source": "werkzeug/datastructures shape", "call": "drop_key({\"a\": 1}, \"a\")",
    "code": "def drop_key(table, key):  # TWIN: NAI-011 del-effect\n    del table[key]\n"},
  ],
  "control": {"fn": "view_name", "call": "view_name(object())", "code": "def view_name(view):  # CONTROL\n    return \"view:\" + type(view).__name__\n"},
 },
 "NAI-087": {
  "plant": {"fn": "row_totals", "what": "the whole-list total recomputed on every pass and appended — the appearance of per-row totals", "call": "row_totals([1, 2])",
            "code": "def row_totals(rows):  # PLANT: NAI-087 loop-invariant call\n    totals = []\n    for row in rows:\n        total = sum(rows)\n        totals.append(total)\n    return totals\n"},
  "twins": [
   {"fn": "row_sizes", "tag": "reads-loop-var", "what": "the call reads the loop variable", "source": "any honest module", "call": "row_sizes([[1], [2, 3]])",
    "code": "def row_sizes(rows):  # TWIN: NAI-087 reads-loop-var\n    sizes = []\n    for row in rows:\n        size = len(row)\n        sizes.append(size)\n    return sizes\n"},
   {"fn": "row_shares", "tag": "hoisted", "what": "the invariant is computed once before the loop", "source": "any honest module", "call": "row_shares([1, 2])",
    "code": "def row_shares(rows):  # TWIN: NAI-087 hoisted\n    total = sum(rows)\n    shares = []\n    for row in rows:\n        shares.append(row / max(total, 1))\n    return shares\n"},
  ],
  "control": {"fn": "row_count", "call": "row_count([1])", "code": "def row_count(rows):  # CONTROL\n    return len(rows)\n"},
 },
}
