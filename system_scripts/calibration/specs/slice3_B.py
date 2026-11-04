"""Slice 3, half B (HELD OUT — the fit never sees it). Same nine families as half A (NAI-005, 024, 034, 041, 062, 109, 200,
201, 213), DIFFERENT shapes: the plant is a different counterfeit form, the twins different honest idioms."""
SLICE = 3; HALF = "B"; SEED = 43; HELD_OUT = True

FAMILIES = {
 "NAI-005": {
  "plant": {"fn": "label_reading", "what": "if-return then an else that assigns the SAME label — a branch in appearance only", "call": "label_reading(5, 3)",
            "code": "def label_reading(value, limit):  # PLANT: NAI-005 redundant else, same outcome\n    if value > limit:\n        return \"over:\" + str(value)\n    else:\n        label = \"over:\" + str(value)\n        return label\n"},
  "twins": [
   {"fn": "reading_band", "tag": "raise-then-body", "what": "a raise in the if, the real body dedented", "source": "packaging/version.py shape", "call": "reading_band(5, 3)",
    "code": "def reading_band(value, limit):  # TWIN: NAI-005 raise-then-body\n    if limit <= 0:\n        raise ValueError(\"limit must be positive\")\n    band = value // limit\n    return band\n"},
   {"fn": "sign_word", "tag": "single-statement-else", "what": "a one-statement else is not flagged", "source": "any honest module", "call": "sign_word(-1)",
    "code": "def sign_word(value):  # TWIN: NAI-005 single-statement-else\n    if value < 0:\n        return \"negative\"\n    else:\n        return \"non-negative\"\n"},
  ],
  "control": {"fn": "over_by", "call": "over_by(5, 3)", "code": "def over_by(value, limit):  # CONTROL\n    return value - limit\n"},
 },
 "NAI-024": {
  "plant": {"fn": "drain_queue", "what": "a while loop that returns on its first pass — drains nothing and calls it a drain", "call": "drain_queue([1, 2])",
            "code": "def drain_queue(queue):  # PLANT: NAI-024 immediate return inside a while loop\n    while queue:\n        return queue[0]\n    return None\n"},
  "twins": [
   {"fn": "join_words", "tag": "append-collect", "what": "collects a transformed item into a local list", "source": "click/formatting.py shape", "call": "join_words([\"a\", \"b\"])",
    "code": "def join_words(words):  # TWIN: NAI-024 append-collect\n    out = []\n    for word in words:\n        out.append(word.upper())\n    return \" \".join(out)\n"},
   {"fn": "count_until", "tag": "break-on-limit", "what": "counts until a limit and breaks", "source": "any honest module", "call": "count_until([1, 5, 2], 3)",
    "code": "def count_until(values, limit):  # TWIN: NAI-024 break-on-limit\n    seen = 0\n    for value in values:\n        if value > limit:\n            break\n        seen += 1\n    return seen\n"},
  ],
  "control": {"fn": "queue_size", "call": "queue_size([1])", "code": "def queue_size(queue):  # CONTROL\n    return len(queue)\n"},
 },
 "NAI-034": {
  "plant": {"fn": "rotate_logs", "what": "a docstring is the whole body behind a working name", "call": "rotate_logs(\"logs\")",
            "code": "def rotate_logs(directory):  # PLANT: NAI-034 docstring-only body\n    \"\"\"Rotate the log files under directory.\"\"\"\n"},
  "twins": [
   {"fn": "render_row", "tag": "not-implemented", "what": "a docstring then raise NotImplementedError — an explicit contract", "source": "urllib3/response.py shape", "call": "render_row.__name__",
    "code": "def render_row(row):  # TWIN: NAI-034 not-implemented\n    \"\"\"Render one row; subclasses provide the format.\"\"\"\n    raise NotImplementedError(\"render_row\")\n"},
   {"fn": "log_name", "tag": "docstring-plus-return", "what": "a docstring followed by a real return", "source": "any honest module", "call": "log_name(\"app\", 2)",
    "code": "def log_name(stem, index):  # TWIN: NAI-034 docstring-plus-return\n    \"\"\"File name for the index-th rotated log.\"\"\"\n    return stem + \".\" + str(index) + \".log\"\n"},
  ],
  "control": {"fn": "is_log", "call": "is_log(\"a.log\")", "code": "def is_log(name):  # CONTROL\n    return name.endswith(\".log\")\n"},
 },
 "NAI-041": {
  "plant": {"fn": "send_to", "what": "the address parameter is overwritten with a fixed host before it is read", "call": "send_to(\"host-a\", \"hi\")",
            "code": "def send_to(address, message):  # PLANT: NAI-041 parameter shadowed by a constant\n    address = \"localhost\"\n    return message + \" -> \" + address\n"},
  "twins": [
   {"fn": "clamp_limit", "tag": "guard-then-store", "what": "the parameter is read in the guard before the store", "source": "any honest module", "call": "clamp_limit(50)",
    "code": "def clamp_limit(limit):  # TWIN: NAI-041 guard-then-store\n    if limit > 10:\n        limit = 10\n    return limit * 2\n"},
   {"fn": "bump", "tag": "aug-assign", "what": "an augmented assignment reads the parameter first", "source": "any honest module", "call": "bump(1)",
    "code": "def bump(count):  # TWIN: NAI-041 aug-assign\n    count += 1\n    return \"n=\" + str(count)\n"},
  ],
  "control": {"fn": "greeting", "call": "greeting(\"x\")", "code": "def greeting(name):  # CONTROL\n    return \"hello \" + name\n"},
 },
 "NAI-062": {
  "plant": {"fn": "has_no_items", "what": "negates a len > 0 comparison — a double re-derivation of the bool", "call": "has_no_items([])",
            "code": "def has_no_items(items):  # PLANT: NAI-062 not (len > 0)\n    return not (len(items) > 0)\n"},
  "twins": [
   {"fn": "is_blank", "tag": "not-value", "what": "plain `not` on the value", "source": "any honest module", "call": "is_blank(\"\")",
    "code": "def is_blank(text):  # TWIN: NAI-062 not-value\n    return not text.strip()\n"},
   {"fn": "at_capacity", "tag": "len-vs-capacity", "what": "len compared to a capacity parameter", "source": "watchdog/utils shape", "call": "at_capacity([1, 2], 2)",
    "code": "def at_capacity(items, capacity):  # TWIN: NAI-062 len-vs-capacity\n    return len(items) >= capacity\n"},
  ],
  "control": {"fn": "last_item", "call": "last_item([1, 2])", "code": "def last_item(items):  # CONTROL\n    return items[-1]\n"},
 },
 "NAI-109": {
  "plant": {"fn": "delete_first", "what": "named delete, inserts a placeholder — the opposite of its name", "call": "delete_first([1, 2])",
            "code": "def delete_first(items):  # PLANT: NAI-109 delete_* that inserts\n    copy = sorted(items)\n    copy.insert(0, None)\n    return copy\n"},
  "twins": [
   {"fn": "delete_last", "tag": "name-matches-body", "what": "named delete, drops the last", "source": "any honest module", "call": "delete_last([1, 2])",
    "code": "def delete_last(items):  # TWIN: NAI-109 name-matches-body\n    return list(items)[:-1]\n"},
   {"fn": "create_row", "tag": "create-appends", "what": "named create, builds and appends", "source": "any honest module", "call": "create_row([], 1)",
    "code": "def create_row(rows, value):  # TWIN: NAI-109 create-appends\n    out = list(rows)\n    out.append({\"value\": value})\n    return out\n"},
  ],
  "control": {"fn": "row_total", "call": "row_total([1, 2])", "code": "def row_total(rows):  # CONTROL\n    return sum(rows)\n"},
 },
 "NAI-200": {
  "plant": {"fn": "safe_import", "what": "named safe, imports a module by name with no error handling", "call": "safe_import(\"json\")", "prelude": "import importlib",
            "code": "def safe_import(name):  # PLANT: NAI-200 risky dynamic import behind a safe_ name\n    return importlib.import_module(name)\n"},
  "twins": [
   {"fn": "import_or_none", "tag": "handled-import", "what": "the import is inside a try that re-raises with context", "source": "pydantic/_internal shape", "call": "import_or_none(\"json\")", "prelude": "import importlib",
    "code": "def import_or_none(name):  # TWIN: NAI-200 handled-import\n    try:\n        return importlib.import_module(name)\n    except ImportError as exc:\n        raise RuntimeError(\"module unavailable: \" + name) from exc\n"},
   {"fn": "module_stem", "tag": "no-risky-call", "what": "no risky call at all", "source": "any honest module", "call": "module_stem(\"a.b.c\")",
    "code": "def module_stem(dotted):  # TWIN: NAI-200 no-risky-call\n    return dotted.rsplit(\".\", 1)[-1]\n"},
  ],
  "control": {"fn": "dotted_depth", "call": "dotted_depth(\"a.b\")", "code": "def dotted_depth(dotted):  # CONTROL\n    return dotted.count(\".\") + 1\n"},
 },
 "NAI-201": {
  "plant": {"fn": "validated_ratio", "what": "named validated, coerces a field of the payload with float() and no guard — validation in name only", "call": "validated_ratio({\"ratio\": \"0.5\"})",
            "code": "def validated_ratio(payload):  # PLANT: NAI-201 unguarded coercion of a parameter's field\n    return float(payload[\"ratio\"])\n"},
  "twins": [
   {"fn": "ratio_of", "tag": "try-guarded", "what": "the coercion is inside a try that re-raises with context", "source": "pydantic/_internal shape", "call": "ratio_of({\"ratio\": \"0.5\"})",
    "code": "def ratio_of(payload):  # TWIN: NAI-201 try-guarded\n    try:\n        return float(payload[\"ratio\"])\n    except (KeyError, TypeError, ValueError) as exc:\n        raise ValueError(\"bad ratio field\") from exc\n"},
   {"fn": "has_ratio", "tag": "no-coercion", "what": "no coercion at all", "source": "any honest module", "call": "has_ratio({\"ratio\": 1})",
    "code": "def has_ratio(payload):  # TWIN: NAI-201 no-coercion\n    return \"ratio\" in payload\n"},
  ],
  "control": {"fn": "percent_label", "call": "percent_label(0.5)", "code": "def percent_label(ratio):  # CONTROL\n    return str(ratio * 100) + \"%\"\n"},
 },
 "NAI-213": {
  "plant": {"fn": "Scheduler", "what": "a class whose body is an ellipsis — a component in name only", "call": "Scheduler.__name__",
            "code": "class Scheduler:  # PLANT: NAI-213 empty class (ellipsis body)\n    ...\n"},
  "twins": [
   {"fn": "late_warning", "tag": "warning-subclass-in-use", "what": "an empty Warning subclass (the idiom) built by a real function", "source": "urllib3/exceptions.py shape", "call": "late_warning(7)", "prelude": "class ScheduleWarning(Warning):  # an empty Warning subclass is the idiom\n    pass",
    "code": "def late_warning(minutes):  # TWIN: NAI-213 warning-subclass-in-use\n    return ScheduleWarning(\"late by \" + str(minutes) + \" min\")\n"},
   {"fn": "slot_after", "tag": "dataclass-in-use", "what": "a decorated class with a field, built by a real function", "source": "any honest module", "call": "slot_after(1, 2)", "prelude": "from dataclasses import dataclass\n\n\n@dataclass\nclass Slot:  # a decorated class with a field\n    start: int = 0",
    "code": "def slot_after(start, minutes):  # TWIN: NAI-213 dataclass-in-use\n    return Slot(start + minutes).start\n"},
  ],
  "control": {"fn": "slot_label", "call": "slot_label(1)", "code": "def slot_label(start):  # CONTROL\n    return \"slot@\" + str(start)\n"},
 },
}
