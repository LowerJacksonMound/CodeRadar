"""Slice 1, half B (HELD OUT — the score corpus). Same families as half A, DIFFERENT shapes: try/except fall-off,
os.remove() sink, unused param on a base-less method, continue-only loop, `from … import` inside the body, early-return read."""
SLICE = 1; HALF = "B"; SEED = 23; HELD_OUT = True
ENTRY_PRELUDE = "import os\nimport tempfile"
ENTRY_SETUP = "scratch = tempfile.NamedTemporaryFile(delete=False).name\nscratch_b = tempfile.NamedTemporaryFile(delete=False).name"

FAMILIES = {
 "NAI-142": {
  "plant": {"fn": "parse_count", "what": "return annotation, the except path falls off the end", "call": "parse_count(\"4\")",
            "code": "def parse_count(text: str) -> int:  # PLANT: NAI-142 annotated int, the except path returns nothing\n    try:\n        return int(text)\n    except ValueError:\n        text = text.strip()\n"},
  "twins": [
   {"fn": "sign_of", "tag": "elif-chain", "what": "if / elif / else — every branch returns", "source": "packaging/version.py shape", "call": "sign_of(-3)",
    "code": "def sign_of(value: int) -> int:  # TWIN: NAI-142 elif-chain\n    if value > 0:\n        return 1\n    elif value < 0:\n        return -1\n    else:\n        return 0\n"},
   {"fn": "count_lines", "tag": "loop-return", "what": "return after the loop on every path", "source": "click/formatting.py shape", "call": "count_lines(\"a\\nb\")",
    "code": "def count_lines(text: str) -> int:  # TWIN: NAI-142 loop-return\n    seen = 0\n    for _line in text.splitlines():\n        seen += 1\n    return seen\n"},
  ],
  "control": {"fn": "strip_text", "call": "strip_text(\" a \")", "code": "def strip_text(text: str) -> str:  # CONTROL\n    return text.strip()\n"},
 },
 "NAI-158": {
  "plant": {"fn": "discard_file", "what": "boundary-named param reaches os.remove() with no validation", "call": "discard_file(scratch)", "prelude": "import os",
            "code": "def discard_file(filepath):  # PLANT: NAI-158 filepath -> remove() sink, no validation\n    os.remove(filepath)\n    return os.path.exists(filepath)\n"},
  "twins": [
   {"fn": "discard_checked", "tag": "verified", "what": "verify() call before the sink", "source": "werkzeug/utils.py safe_join shape", "call": "discard_checked(scratch_b)", "prelude": "import os\n\n\ndef verify(filepath):\n    return isinstance(filepath, str) and os.path.isfile(filepath)",
    "code": "def discard_checked(filepath):  # TWIN: NAI-158 verified\n    if not verify(filepath):\n        raise ValueError(\"not a file\")\n    os.remove(filepath)\n    return os.path.exists(filepath)\n"},
   {"fn": "name_only", "tag": "no-sink", "what": "boundary-named param used for a string only", "source": "click/utils.py shape", "call": "name_only(\"a/b.txt\")",
    "code": "def name_only(filepath):  # TWIN: NAI-158 no-sink\n    return filepath.rsplit(\"/\", 1)[-1]\n"},
  ],
  "control": {"fn": "ext_of", "call": "ext_of(\"a.b\")", "code": "def ext_of(name):  # CONTROL\n    return name.rsplit(\".\", 1)[-1]\n"},
 },
 "NAI-003": {
  "plant": {"fn": "Ledger", "what": "method on a base-less class with an unused param (memo)", "call": "Ledger().add(3, \"m\")",
            "code": "class Ledger:\n    \"\"\"Running total.\"\"\"\n\n    def __init__(self):\n        self.total = 0\n\n    def add(self, amount, memo):  # PLANT: NAI-003 memo never read\n        self.total = self.total + amount\n        return self.total\n"},
  "twins": [
   {"fn": "pair_with", "tag": "dummy-default", "what": "unused positional-with-default param is dummy-named (_memo)", "source": "ruff ARG001 dummy-variable-rgx (NAI-100 is NAME-gated: `add_*` fires it whatever the body — slice-2 evidence)", "call": "pair_with(3, \"m\")",
    "code": "def pair_with(amount, _memo=\"\"):  # TWIN: NAI-003 dummy-default\n    return amount + amount\n"},
   {"fn": "add_labelled", "tag": "read-param", "what": "every param is read (memo becomes the label)", "source": "any honest pair", "call": "add_labelled(1, \"m\")",
    "code": "def add_labelled(amount, memo):  # TWIN: NAI-003 read-param\n    label = str(memo)\n    return amount + amount, label\n"},
  ],
  "control": {"fn": "pair_sum", "call": "pair_sum(1, 2)", "code": "def pair_sum(left, right):  # CONTROL\n    return left + right\n"},
 },
 "NAI-015": {
  "plant": {"fn": "skip_rows", "what": "loop whose body is only continue", "call": "skip_rows([1, 2])",
            "code": "def skip_rows(rows):  # PLANT: NAI-015 continue-only loop\n    for _ in rows:\n        continue\n    return len(rows)\n"},
  "twins": [
   {"fn": "join_rows", "tag": "collect-join", "what": "loop collects parts then joins", "source": "jinja2/utils.py shape", "call": "join_rows([1, 5, 2])",
    "code": "def join_rows(rows):  # TWIN: NAI-015 collect-join\n    parts = []\n    for row in rows:\n        parts.append(str(row))\n    return \",\".join(parts)\n"},
   {"fn": "index_rows", "tag": "dict-build", "what": "loop builds a dict", "source": "importlib_metadata shape", "call": "index_rows([\"a\", \"b\"])",
    "code": "def index_rows(rows):  # TWIN: NAI-015 dict-build\n    table = {}\n    for position, row in enumerate(rows):\n        table[row] = position\n    return table\n"},
  ],
  "control": {"fn": "row_count", "call": "row_count([1])", "code": "def row_count(rows):  # CONTROL\n    return len(rows)\n"},
 },
 "NAI-008": {
  "plant": {"fn": "dump_record", "what": "from-import as a direct child of the function body", "call": "dump_record({\"a\": 1})",
            "code": "def dump_record(record):  # PLANT: NAI-008 from-import inside the body\n    from json import dumps\n    return dumps(record)\n"},
  "twins": [
   {"fn": "dump_module", "tag": "module-from-import", "what": "module-level from-import used in the body", "source": "any honest module", "call": "dump_module({\"a\": 1})", "prelude": "from json import dumps",
    "code": "def dump_module(record):  # TWIN: NAI-008 module-from-import\n    return dumps(record)\n"},
   {"fn": "write_rows", "tag": "guarded", "what": "conditional import under try/except ImportError", "source": "urllib3/util/ssl_.py shape", "call": "write_rows([[1, 2]])",
    "code": "def write_rows(rows):  # TWIN: NAI-008 guarded\n    try:\n        import csv as codec\n    except ImportError as exc:\n        raise RuntimeError(\"csv missing\") from exc\n    return codec.excel.delimiter.join(str(len(row)) for row in rows)\n"},
  ],
  "control": {"fn": "lower_word", "call": "lower_word(\"A\")", "code": "def lower_word(word):  # CONTROL\n    return word.lower()\n"},
 },
 "NAI-145": {
  "plant": {"fn": "summarize_items", "what": "name read on the empty-input early return before its assignment", "call": "summarize_items([1])",
            "code": "def summarize_items(items):  # PLANT: NAI-145 count read before it is assigned\n    if not items:\n        return count\n    count = len(items)\n    return count\n"},
  "twins": [
   {"fn": "summarize_defined", "tag": "def-first", "what": "assigned before the early return reads it", "source": "any honest guard", "call": "summarize_defined([1])",
    "code": "def summarize_defined(items):  # TWIN: NAI-145 def-first\n    count = len(items)\n    if not items:\n        return count\n    return count + 1\n"},
   {"fn": "read_setting", "tag": "closure", "what": "a name never assigned locally (closure / module name)", "source": "flask/globals.py shape", "call": "read_setting()", "prelude": "SETTING = 7",
    "code": "def read_setting():  # TWIN: NAI-145 closure\n    return SETTING + 1\n"},
  ],
  "control": {"fn": "last_item", "call": "last_item([3])", "code": "def last_item(items):  # CONTROL\n    return items[-1]\n"},
 },
}
