"""Slice 1, half A (the FIT corpus). Families NAI-142, 158, 003, 015, 008, 145. Shapes here are the `if`-fall-off / open() /
unused positional / pass-loop / plain import / verbose-branch forms; half B uses DIFFERENT shapes for the same families."""
SLICE = 1; HALF = "A"; SEED = 11; HELD_OUT = False

FAMILIES = {
 "NAI-142": {
  "plant": {"fn": "pick_positive", "what": "return annotation, falls off the end when value <= 0", "call": "pick_positive(3)",
            "code": "def pick_positive(value: int) -> int:  # PLANT: NAI-142 annotated int, no return on the value <= 0 path\n    if value > 0:\n        return value\n"},
  "twins": [
   {"fn": "clamp_positive", "tag": "every-path", "what": "every path returns", "source": "click/core.py invoke shape", "call": "clamp_positive(-2)",
    "code": "def clamp_positive(value: int) -> int:  # TWIN: NAI-142 every-path\n    if value > 0:\n        return value\n    return 0\n"},
   {"fn": "check_positive", "tag": "none-annotated", "what": "annotated -> None, no return owed", "source": "watchdog observers shape", "call": "check_positive(4)",
    "code": "def check_positive(value: int) -> None:  # TWIN: NAI-142 none-annotated\n    if value <= 0:\n        raise ValueError(\"value must be positive\")\n"},
  ],
  "control": {"fn": "double_value", "call": "double_value(5)", "code": "def double_value(value: int) -> int:  # CONTROL\n    return value + value\n"},
 },
 "NAI-158": {
  "plant": {"fn": "read_config", "what": "boundary-named param reaches open() with no validation", "call": "read_config(__file__)",
            "code": "def read_config(path):  # PLANT: NAI-158 path -> open() sink, no validation\n    with open(path, encoding=\"utf-8\") as fh:\n        return fh.read()\n"},
  "twins": [
   {"fn": "read_checked", "tag": "validated", "what": "isinstance check before the sink", "source": "flask/helpers.py send_file shape", "call": "read_checked(__file__)",
    "code": "def read_checked(path):  # TWIN: NAI-158 validated\n    if not isinstance(path, str):\n        raise TypeError(\"path must be str\")\n    try:\n        with open(path, encoding=\"utf-8\") as fh:\n            return fh.read()\n    except OSError as exc:\n        raise RuntimeError(\"unreadable: \" + path) from exc\n"},
   {"fn": "label_path", "tag": "no-sink", "what": "boundary-named param never reaches a sink", "source": "click/utils.py format_filename shape", "call": "label_path(\"a/b\")",
    "code": "def label_path(path):  # TWIN: NAI-158 no-sink\n    return \"file: \" + path\n"},
  ],
  "control": {"fn": "join_parts", "call": "join_parts(\"a\", \"b\")", "code": "def join_parts(head, tail):  # CONTROL\n    return head + \"/\" + tail\n"},
 },
 "NAI-003": {
  "plant": {"fn": "scale_value", "what": "declared positional param never referenced", "call": "scale_value(2, 9)",
            "code": "def scale_value(value, factor):  # PLANT: NAI-003 factor never read\n    return value + value\n"},
  "twins": [
   {"fn": "scale_dummy", "tag": "dummy-named", "what": "unused param is dummy-named (_factor)", "source": "ruff ARG001 dummy-variable-rgx", "call": "scale_dummy(2, 9)",
    "code": "def scale_dummy(value, _factor):  # TWIN: NAI-003 dummy-named\n    return value + value\n"},
   {"fn": "scale_options", "tag": "dummy-kwarg", "what": "unused keyword param is dummy-named (_options=None)", "source": "ruff ARG001 dummy-variable-rgx", "call": "scale_options(2)",
    "code": "def scale_options(value, _options=None):  # TWIN: NAI-003 dummy-kwarg\n    return value + value\n"},
  ],
  "control": {"fn": "add_values", "call": "add_values(1, 2)", "code": "def add_values(left, right):  # CONTROL\n    return left + right\n"},
 },
 "NAI-015": {
  "plant": {"fn": "drain_items", "what": "loop whose body is only pass", "call": "drain_items([1, 2])",
            "code": "def drain_items(items):  # PLANT: NAI-015 pass-only loop\n    for _ in items:\n        pass\n    return len(items)\n"},
  "twins": [
   {"fn": "sum_items", "tag": "accumulate", "what": "loop accumulates into a total", "source": "packaging/version.py shape", "call": "sum_items([1, 2])",
    "code": "def sum_items(items):  # TWIN: NAI-015 accumulate\n    total = 0\n    for item in items:\n        total += item\n    return total\n"},
   {"fn": "keep_odd", "tag": "append", "what": "loop appends to a result list", "source": "click/parser.py shape", "call": "keep_odd([1, 2, 3])",
    "code": "def keep_odd(items):  # TWIN: NAI-015 append\n    kept = []\n    for item in items:\n        if item % 2:\n            kept.append(item)\n    return kept\n"},
  ],
  "control": {"fn": "count_items", "call": "count_items([1])", "code": "def count_items(items):  # CONTROL\n    return len(items)\n"},
 },
 "NAI-008": {
  "plant": {"fn": "stamp_now", "what": "import statement as a direct child of the function body", "call": "stamp_now()",
            "code": "def stamp_now():  # PLANT: NAI-008 import inside the body\n    import datetime\n    return datetime.datetime.now().isoformat()\n"},
  "twins": [
   {"fn": "stamp_module", "tag": "module-import", "what": "module-level import used in the body", "source": "any honest module", "call": "stamp_module()", "prelude": "import datetime",
    "code": "def stamp_module():  # TWIN: NAI-008 module-import\n    return datetime.datetime.now().isoformat()\n"},
   {"fn": "encode_record", "tag": "guarded", "what": "conditional import under try/except ImportError", "source": "requests/compat.py shape", "call": "encode_record({\"a\": 1})",
    "code": "def encode_record(record):  # TWIN: NAI-008 guarded\n    try:\n        import ujson as codec\n    except ImportError:\n        import json as codec\n    return codec.dumps(record)\n"},
  ],
  "control": {"fn": "upper_word", "call": "upper_word(\"a\")", "code": "def upper_word(word):  # CONTROL\n    return word.upper()\n"},
 },
 "NAI-145": {
  "plant": {"fn": "tally_values", "what": "name read on the verbose branch before its first assignment", "call": "tally_values([1, 2])",
            "code": "def tally_values(values, verbose=False):  # PLANT: NAI-145 total read before it is assigned\n    if verbose:\n        return str(total)\n    total = 0\n    for value in values:\n        total += value\n    return total\n"},
  "twins": [
   {"fn": "tally_defined", "tag": "def-first", "what": "assigned before every read", "source": "any honest accumulator", "call": "tally_defined([1, 2])",
    "code": "def tally_defined(values):  # TWIN: NAI-145 def-first\n    total = 0\n    for value in values:\n        total += value\n    return total\n"},
   {"fn": "bump_counter", "tag": "global", "what": "a global declared in the function", "source": "run 19 ruling: a global is defined by its module", "call": "bump_counter()", "prelude": "COUNTER = 0",
    "code": "def bump_counter():  # TWIN: NAI-145 global\n    global COUNTER\n    COUNTER = COUNTER + 1\n    return COUNTER\n"},
  ],
  "control": {"fn": "first_value", "call": "first_value([3])", "code": "def first_value(values):  # CONTROL\n    return values[0]\n"},
 },
}
