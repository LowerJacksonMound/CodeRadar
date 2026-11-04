"""Slice 2, half B (HELD OUT). Same eleven families as half A, DIFFERENT shapes: while-loop overwrite, subscript-store mutation,
subtract-that-adds, docstring-only body, twin ifs with identical bodies, `is False`, assert isinstance, elif chain of assigns,
subprocess.run of a raw parameter. Never loaded by the fit."""
SLICE = 2; HALF = "B"; SEED = 29; HELD_OUT = True

FAMILIES = {
 "NAI-037": {
  "plant": {"fn": "count_words", "what": "named count, returns the last line's word count — overwrite, no accumulation", "call": "count_words([\"a b\", \"c\"])",
            "code": "def count_words(lines):  # PLANT: NAI-037 overwrite in a for loop over lines\n    count = 0\n    for line in lines:\n        count = len(line.split())\n    return count\n"},
  "twins": [
   {"fn": "word_total", "tag": "while-accumulate", "what": "a while loop accumulating with +=", "source": "any honest module", "call": "word_total([\"a b\", \"c\"])",
    "code": "def word_total(lines):  # TWIN: NAI-037 while-accumulate\n    count = 0\n    index = 0\n    while index < len(lines):\n        count += len(lines[index].split())\n        index += 1\n    return count\n"},
   {"fn": "joined_lines", "tag": "collect", "what": "collects into a list then joins", "source": "jinja2/utils.py shape", "call": "joined_lines([\"a\", \"b\"])",
    "code": "def joined_lines(lines):  # TWIN: NAI-037 collect\n    parts = []\n    for line in lines:\n        parts.append(line.strip())\n    return \" \".join(parts)\n"},
  ],
  "control": {"fn": "line_count", "call": "line_count([\"a\"])", "code": "def line_count(lines):  # CONTROL\n    return len(lines)\n"},
 },
 "NAI-091": {
  "plant": {"fn": "tag_entry", "what": "stores into the caller's dict — subscript mutation of a parameter", "call": "tag_entry({}, \"k\", 1)",
            "code": "def tag_entry(table, key, value):  # PLANT: NAI-091 subscript store on a parameter\n    table[key] = value\n    return len(table)\n"},
  "twins": [
   {"fn": "tagged_copy", "tag": "copy-dict", "what": "copies the mapping first", "source": "flask/templating.py shape", "call": "tagged_copy({}, \"k\", 1)",
    "code": "def tagged_copy(table, key, value):  # TWIN: NAI-091 copy-dict\n    out = dict(table)\n    out[key] = value\n    return (len(out), key, value)\n"},
   {"fn": "merged_items", "tag": "extend-local", "what": "extends a fresh local copy", "source": "werkzeug/routing shape", "call": "merged_items([1], [2])",
    "code": "def merged_items(items, extra):  # TWIN: NAI-091 extend-local\n    out = list(items)\n    out.extend(extra)\n    return len(out) + len(extra)\n"},
  ],
  "control": {"fn": "key_count", "call": "key_count({\"a\": 1})", "code": "def key_count(table):  # CONTROL\n    return len(table)\n"},
 },
 "NAI-104": {
  "plant": {"fn": "subtract_from", "what": "named subtract, merely picks the larger operand — no operator at all", "call": "subtract_from(5, 2)",
            "code": "def subtract_from(total, part):  # PLANT: NAI-104 name says subtract, body picks the larger (no operator, no call)\n    return total if total > part else part\n"},
  "twins": [
   {"fn": "subtract_pair", "tag": "operator-present", "what": "the named operator is present", "source": "any honest module", "call": "subtract_pair(5, 2)",
    "code": "def subtract_pair(total, part):  # TWIN: NAI-104 operator-present\n    return total - part\n"},
   {"fn": "divide_evenly", "tag": "divide", "what": "named divide, divides (guarded divisor)", "source": "any honest module", "call": "divide_evenly(6, 3)",
    "code": "def divide_evenly(total, parts):  # TWIN: NAI-104 divide\n    return total / max(parts, 1)\n"},
  ],
  "control": {"fn": "as_pair", "call": "as_pair(1, 2)", "code": "def as_pair(total, part):  # CONTROL\n    return (total, part)\n"},
 },
 "NAI-120": {
  "plant": {"fn": "close_handle", "what": "docstring-only body behind a working name", "call": "close_handle(1)",
            "code": "def close_handle(handle):  # PLANT: NAI-120 docstring-only body\n    \"\"\"Close the handle and release its resources.\"\"\"\n"},
  "twins": [
   {"fn": "handle_label", "tag": "real-body", "what": "one real statement", "source": "any honest module", "call": "handle_label(1)",
    "code": "def handle_label(handle):  # TWIN: NAI-120 real-body\n    return \"handle:\" + str(handle)\n"},
   {"fn": "Reader", "tag": "abstractmethod", "what": "docstring-only body under @abstractmethod", "source": "packaging/specifiers.py shape", "call": "Reader.__name__", "prelude": "from abc import ABC, abstractmethod",
    "code": "class Reader(ABC):  # TWIN: NAI-120 abstractmethod\n    @abstractmethod\n    def read_row(self):\n        \"\"\"Read one row from the source.\"\"\"\n"},
  ],
  "control": {"fn": "triple_n", "call": "triple_n(2)", "code": "def triple_n(n):  # CONTROL\n    return n * 3\n"},
 },
 "NAI-040": {
  "plant": {"fn": "apply_flags", "what": "two separate ifs with identical two-statement bodies", "call": "apply_flags(True, False)",
            "code": "def apply_flags(first, second):  # PLANT: NAI-040 duplicate subtrees across two ifs\n    mode = 0\n    level = 0\n    if first:\n        mode = 1\n        level = 2\n    if second:\n        mode = 1\n        level = 2\n    return (mode, level)\n"},
  "twins": [
   {"fn": "apply_modes", "tag": "distinct-bodies", "what": "the two if bodies differ", "source": "any honest module", "call": "apply_modes(True, False)",
    "code": "def apply_modes(first, second):  # TWIN: NAI-040 distinct-bodies\n    mode = 0\n    level = 0\n    if first:\n        mode = 1\n        level = 2\n    if second:\n        mode = 3\n        level = 4\n    return (mode, level)\n"},
   {"fn": "flag_sum", "tag": "no-branches", "what": "arithmetic, no branch", "source": "any honest module", "call": "flag_sum(True, False)",
    "code": "def flag_sum(first, second):  # TWIN: NAI-040 no-branches\n    return (1 if first else 0) + (1 if second else 0)\n"},
  ],
  "control": {"fn": "either", "call": "either(True, False)", "code": "def either(first, second):  # CONTROL\n    return first or second\n"},
 },
 "NAI-061": {
  "plant": {"fn": "pending_count", "what": "identity comparison to False and a re-derived result", "call": "pending_count(False, 3)",
            "code": "def pending_count(done, total):  # PLANT: NAI-061 is False\n    if done is False:\n        return total\n    return 0\n"},
  "twins": [
   {"fn": "remaining", "tag": "not-x", "what": "plain `not done`", "source": "any honest module", "call": "remaining(False, 3)",
    "code": "def remaining(done, total):  # TWIN: NAI-061 not-x\n    if not done:\n        return total\n    return 0\n"},
   {"fn": "first_or_none", "tag": "is-not-None", "what": "identity check against None", "source": "any honest module", "call": "first_or_none([1])",
    "code": "def first_or_none(items):  # TWIN: NAI-061 is-not-None\n    head = items[0] if items else None\n    if head is not None:\n        return head\n    return \"none\"\n"},
  ],
  "control": {"fn": "all_done", "call": "all_done([True])", "code": "def all_done(flags):  # CONTROL\n    return all(flags)\n"},
 },
 "NAI-096": {
  "plant": {"fn": "open_named", "what": "type check of a parameter by assert — gone under -O", "call": "open_named(\"a\")",
            "code": "def open_named(name):  # PLANT: NAI-096 assert isinstance on a parameter\n    assert isinstance(name, str), \"name must be str\"\n    return \"<\" + name + \">\"\n"},
  "twins": [
   {"fn": "open_checked", "tag": "raise", "what": "TypeError raised explicitly", "source": "click/types.py shape", "call": "open_checked(\"a\")",
    "code": "def open_checked(name):  # TWIN: NAI-096 raise\n    if not isinstance(name, str):\n        raise TypeError(\"name must be str\")\n    return \"<\" + name + \">\"\n"},
   {"fn": "wrap_name", "tag": "assert-on-local", "what": "asserts an internal invariant", "source": "werkzeug/routing shape", "call": "wrap_name(\"a\")",
    "code": "def wrap_name(name):  # TWIN: NAI-096 assert-on-local\n    wrapped = \"<\" + name + \">\"\n    assert wrapped.startswith(\"<\"), \"wrapping invariant\"\n    return wrapped\n"},
  ],
  "control": {"fn": "wrap_plain", "call": "wrap_plain(\"a\")", "code": "def wrap_plain(name):  # CONTROL\n    return \"<\" + name + \">\"\n"},
 },
 "NAI-053": {
  "plant": {"fn": "kind_weight", "what": "elif chain assigning the same value in two branches", "call": "kind_weight(\"a\")",
            "code": "def kind_weight(kind):  # PLANT: NAI-053 identical elif bodies\n    if kind == \"a\":\n        weight = 1\n    elif kind == \"b\":\n        weight = 1\n    else:\n        weight = 0\n    return weight\n"},
  "twins": [
   {"fn": "kind_rank", "tag": "distinct", "what": "each branch assigns a different value", "source": "any honest module", "call": "kind_rank(\"a\")",
    "code": "def kind_rank(kind):  # TWIN: NAI-053 distinct\n    if kind == \"a\":\n        rank = 2\n    elif kind == \"b\":\n        rank = 1\n    else:\n        rank = 0\n    return rank\n"},
   {"fn": "kind_table", "tag": "mapping", "what": "a lookup instead of a chain", "source": "any honest module", "call": "kind_table(\"a\")",
    "code": "def kind_table(kind):  # TWIN: NAI-053 mapping\n    return {\"a\": 2, \"b\": 1}.get(kind, 0)\n"},
  ],
  "control": {"fn": "kind_upper", "call": "kind_upper(\"a\")", "code": "def kind_upper(kind):  # CONTROL\n    return kind.upper()\n"},
 },
 "NAI-160": {
  "plant": {"fn": "run_command", "what": "a raw parameter handed to subprocess.run", "call": "run_command([\"true\"])", "prelude": "import subprocess",
            "code": "def run_command(command):  # PLANT: NAI-160 unvalidated input into subprocess.run\n    return subprocess.run(command, capture_output=True).returncode\n"},
  "twins": [
   {"fn": "run_checked", "tag": "validated", "what": "type and content checked before the sink", "source": "click/_termui_impl.py shape", "call": "run_checked([\"true\"])", "prelude": "import subprocess",
    "code": "def run_checked(command):  # TWIN: NAI-160 validated\n    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):\n        raise TypeError(\"command must be a list of str\")\n    return subprocess.run(command, capture_output=True).returncode\n"},
   {"fn": "command_label", "tag": "no-sink", "what": "the parameter never reaches a sink", "source": "click/utils.py shape", "call": "command_label([\"true\"])",
    "code": "def command_label(command):  # TWIN: NAI-160 no-sink\n    return \" \".join(command)\n"},
  ],
  "control": {"fn": "count_parts", "call": "count_parts([\"a\"])", "code": "def count_parts(command):  # CONTROL\n    return len(command)\n"},
 },
 "NAI-011": {
  "plant": {"fn": "warm_cache", "what": "no return, no call, no assignment — a subscript read as the whole body", "call": "warm_cache([1])",
            "code": "def warm_cache(cache):  # PLANT: NAI-011 no return, no effect (subscript read)\n    cache[0]\n"},
  "twins": [
   {"fn": "cache_head", "tag": "returns", "what": "returns the value", "source": "any honest module", "call": "cache_head([1])",
    "code": "def cache_head(cache):  # TWIN: NAI-011 returns\n    return cache[0] + 1\n"},
   {"fn": "forget_head", "tag": "del-effect", "what": "a del statement is the effect", "source": "werkzeug/datastructures shape", "call": "forget_head([1, 2])",
    "code": "def forget_head(cache):  # TWIN: NAI-011 del-effect\n    del cache[0]\n"},
  ],
  "control": {"fn": "cache_size", "call": "cache_size([1])", "code": "def cache_size(cache):  # CONTROL\n    return len(cache)\n"},
 },
 "NAI-087": {
  "plant": {"fn": "queue_sizes", "what": "a while loop recomputing the same len() every pass", "call": "queue_sizes([1, 2])",
            "code": "def queue_sizes(queue):  # PLANT: NAI-087 loop-invariant call in a while loop\n    out = []\n    index = 0\n    while index < len(queue):\n        size = len(queue)\n        out.append(size)\n        index += 1\n    return out\n"},
  "twins": [
   {"fn": "queue_items", "tag": "reads-loop-bound", "what": "the call reads a name bound in the loop", "source": "any honest module", "call": "queue_items([\"a\"])",
    "code": "def queue_items(queue):  # TWIN: NAI-087 reads-loop-bound\n    out = []\n    index = 0\n    while index < len(queue):\n        item = str(queue[index])\n        out.append(item)\n        index += 1\n    return out\n"},
   {"fn": "queue_labels", "tag": "hoisted", "what": "the invariant hoisted above the loop", "source": "any honest module", "call": "queue_labels([\"a\"])",
    "code": "def queue_labels(queue):  # TWIN: NAI-087 hoisted\n    width = len(queue)\n    out = []\n    for item in queue:\n        out.append(str(item) + \"/\" + str(width))\n    return out\n"},
  ],
  "control": {"fn": "queue_len", "call": "queue_len([1])", "code": "def queue_len(queue):  # CONTROL\n    return len(queue)\n"},
 },
}
