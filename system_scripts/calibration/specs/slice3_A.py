"""Slice 3, half A (the FIT corpus). Families admitted by the repo-by-repo fit of 2026-09-06 on 15 calibration libraries
(10 wheels + numpy + the sdists attrs, rich, more-itertools, tomli-w; k = 7 confirmed repos, 0 counterfeit, 0 gap):
NAI-005, 024, 034, 041, 062, 109, 200, 201, 213. Every plant is a COUNTERFEIT — the appearance of work; every twin is an
honest shape that must PASS under the current instrument. Half B uses DIFFERENT shapes."""
SLICE = 3; HALF = "A"; SEED = 41; HELD_OUT = False

FAMILIES = {
 "NAI-005": {
  "plant": {"fn": "safe_get", "what": "if-return then an else that hands back a marker string — the appearance of a safe lookup", "call": "safe_get({\"a\": 1}, \"b\")",
            "code": "def safe_get(mapping, key):  # PLANT: NAI-005 redundant else that fakes a fallback\n    if key in mapping:\n        return mapping[key]\n    else:\n        fallback = str(key) + \"?\"\n        return fallback\n"},
  "twins": [
   {"fn": "lookup_or_label", "tag": "early-return", "what": "if-return then the dedented fallback", "source": "click/core.py shape", "call": "lookup_or_label({\"a\": 1}, \"b\")",
    "code": "def lookup_or_label(mapping, key):  # TWIN: NAI-005 early-return\n    if key in mapping:\n        return mapping[key]\n    label = \"missing:\" + str(key)\n    return label\n"},
   {"fn": "grade", "tag": "elif-chain", "what": "if / elif / else — an elif chain is not a redundant else", "source": "any honest module", "call": "grade(75)",
    "code": "def grade(score):  # TWIN: NAI-005 elif-chain\n    if score >= 90:\n        return \"A\"\n    elif score >= 70:\n        return \"B\"\n    else:\n        return \"C\"\n"},
  ],
  "control": {"fn": "key_count", "call": "key_count({\"a\": 1})", "code": "def key_count(mapping):  # CONTROL\n    return len(mapping)\n"},
 },
 "NAI-024": {
  "plant": {"fn": "scan_values", "what": "named scan, returns on the first pass — the appearance of a scan", "call": "scan_values([3, 9, 4])",
            "code": "def scan_values(values):  # PLANT: NAI-024 immediate return inside the loop\n    for value in values:\n        return value\n    return None\n"},
  "twins": [
   {"fn": "first_over", "tag": "guarded-return", "what": "the return sits behind a condition", "source": "packaging/specifiers.py shape", "call": "first_over([3, 9, 4], 5)",
    "code": "def first_over(values, limit):  # TWIN: NAI-024 guarded-return\n    for value in values:\n        if value > limit:\n            return value\n    return None\n"},
   {"fn": "sum_values", "tag": "aug-accumulate", "what": "accumulates with +=", "source": "any honest module", "call": "sum_values([3, 9, 4])",
    "code": "def sum_values(values):  # TWIN: NAI-024 aug-accumulate\n    total = 0\n    for value in values:\n        total += value\n    return total\n"},
  ],
  "control": {"fn": "value_count", "call": "value_count([1, 2])", "code": "def value_count(values):  # CONTROL\n    return len(values)\n"},
 },
 "NAI-034": {
  "plant": {"fn": "save_report", "what": "a docstring is the whole body behind a working name", "call": "save_report(\"r\", \"out.txt\")",
            "code": "def save_report(report, path):  # PLANT: NAI-034 docstring-only body\n    \"\"\"Write the report to path.\"\"\"\n"},
  "twins": [
   {"fn": "count_rows", "tag": "docstring-plus-loop", "what": "a docstring followed by a real loop", "source": "any honest module", "call": "count_rows([\"a\", \"b\"])",
    "code": "def count_rows(report):  # TWIN: NAI-034 docstring-plus-loop\n    \"\"\"Count the rows of a report.\"\"\"\n    total = 0\n    for _row in report:\n        total += 1\n    return total\n"},
   {"fn": "report_title", "tag": "docstring-plus-body", "what": "a docstring followed by a real statement", "source": "any honest module", "call": "report_title(\"q1\")",
    "code": "def report_title(name):  # TWIN: NAI-034 docstring-plus-body\n    \"\"\"Title line for a report.\"\"\"\n    return \"Report: \" + str(name)\n"},
  ],
  "control": {"fn": "line_count", "call": "line_count(\"a\\nb\")", "code": "def line_count(text):  # CONTROL\n    return text.count(\"\\n\") + 1\n"},
 },
 "NAI-041": {
  "plant": {"fn": "scale_reading", "what": "the factor parameter is overwritten before it is read — the appearance of a parameter", "call": "scale_reading(4, 3)",
            "code": "def scale_reading(value, factor):  # PLANT: NAI-041 parameter shadowed before use\n    factor = 1\n    return value * factor\n"},
  "twins": [
   {"fn": "scale_or_unit", "tag": "read-then-store", "what": "the parameter is read in the guard before the store", "source": "click/core.py shape", "call": "scale_or_unit(4, 0)",
    "code": "def scale_or_unit(value, factor):  # TWIN: NAI-041 read-then-store\n    if not factor:\n        factor = 1\n    return value * factor\n"},
   {"fn": "clean_label", "tag": "method-on-param", "what": "the parameter is transformed through its own method", "source": "jinja2/filters.py shape", "call": "clean_label(\" x \")",
    "code": "def clean_label(text):  # TWIN: NAI-041 method-on-param\n    text = text.strip()\n    return text.lower()\n"},
  ],
  "control": {"fn": "halve", "call": "halve(4)", "code": "def halve(value):  # CONTROL\n    return value / 2\n"},
 },
 "NAI-062": {
  "plant": {"fn": "has_entries", "what": "compares len to zero and re-derives the bool — the appearance of logic", "call": "has_entries([1])",
            "code": "def has_entries(entries):  # PLANT: NAI-062 len > 0 then True/False\n    if len(entries) > 0:\n        return True\n    return False\n"},
  "twins": [
   {"fn": "first_or_default", "tag": "truthiness", "what": "plain truthiness on the collection", "source": "any honest module", "call": "first_or_default([], 0)",
    "code": "def first_or_default(entries, default):  # TWIN: NAI-062 truthiness\n    if not entries:\n        return default\n    return entries[0]\n"},
   {"fn": "needs_paging", "tag": "len-vs-limit", "what": "len compared to a real limit, through a local", "source": "werkzeug/datastructures shape", "call": "needs_paging([1, 2, 3], 2)",
    "code": "def needs_paging(entries, page_size):  # TWIN: NAI-062 len-vs-limit\n    count = len(entries)\n    return count > page_size\n"},
  ],
  "control": {"fn": "entry_pair", "call": "entry_pair(1, 2)", "code": "def entry_pair(a, b):  # CONTROL\n    return (a, b)\n"},
 },
 "NAI-109": {
  "plant": {"fn": "remove_marker", "what": "named remove, appends a marker — the opposite of its name", "call": "remove_marker(\"ab\")",
            "code": "def remove_marker(text):  # PLANT: NAI-109 remove_* that appends\n    parts = list(text)\n    parts.append(\"*\")\n    return \"\".join(parts)\n"},
  "twins": [
   {"fn": "remove_spaces", "tag": "name-matches-body", "what": "named remove, removes", "source": "any honest module", "call": "remove_spaces(\"a b\")",
    "code": "def remove_spaces(text):  # TWIN: NAI-109 name-matches-body\n    return text.replace(\" \", \"\")\n"},
   {"fn": "add_marker", "tag": "add-appends", "what": "named add, appends", "source": "any honest module", "call": "add_marker(\"ab\")",
    "code": "def add_marker(text):  # TWIN: NAI-109 add-appends\n    parts = list(text)\n    parts.append(\"*\")\n    return \"\".join(parts)\n"},
  ],
  "control": {"fn": "marker_count", "call": "marker_count(\"a*b*\")", "code": "def marker_count(text):  # CONTROL\n    return text.count(\"*\")\n"},
 },
 "NAI-200": {
  "plant": {"fn": "safe_parse_settings", "what": "named safe, parses JSON with no error handling — the appearance of safety", "call": "safe_parse_settings('{\"a\": 1}')", "prelude": "import json",
            "code": "def safe_parse_settings(payload):  # PLANT: NAI-200 risky call, no handling, behind a safe_ name\n    return json.loads(payload)\n"},
  "twins": [
   {"fn": "parse_settings", "tag": "handled", "what": "the risky call is inside a try that re-raises with context", "source": "packaging/metadata.py shape", "call": "parse_settings('{\"a\": 1}')", "prelude": "import json",
    "code": "def parse_settings(payload):  # TWIN: NAI-200 handled\n    try:\n        return json.loads(payload)\n    except ValueError as exc:\n        raise RuntimeError(\"bad settings\") from exc\n"},
   {"fn": "split_settings", "tag": "no-risky-call", "what": "no risky call at all", "source": "any honest module", "call": "split_settings(\"a=1;b=2\")",
    "code": "def split_settings(text):  # TWIN: NAI-200 no-risky-call\n    return text.split(\";\")\n"},
  ],
  "control": {"fn": "setting_key", "call": "setting_key(\"a=1\")", "code": "def setting_key(pair):  # CONTROL\n    return pair.partition(\"=\")[0]\n"},
 },
 "NAI-201": {
  "plant": {"fn": "safe_int", "what": "named safe, coerces the parameter with int() and no guard — safety in name only", "call": "safe_int(\"7\")",
            "code": "def safe_int(text):  # PLANT: NAI-201 unguarded coercion behind a safe_ name\n    return int(text)\n"},
  "twins": [
   {"fn": "parse_int", "tag": "try-guarded", "what": "the coercion is inside a try that re-raises with context", "source": "click/types.py shape", "call": "parse_int(\"7\")",
    "code": "def parse_int(text):  # TWIN: NAI-201 try-guarded\n    try:\n        return int(text)\n    except ValueError as exc:\n        raise ValueError(\"not an integer: \" + text) from exc\n"},
   {"fn": "digit_count", "tag": "no-coercion", "what": "no coercion at all", "source": "any honest module", "call": "digit_count(\"a1b22\")",
    "code": "def digit_count(text):  # TWIN: NAI-201 no-coercion\n    return sum(1 for ch in text if ch.isdigit())\n"},
  ],
  "control": {"fn": "pad_left", "call": "pad_left(\"7\", 3)", "code": "def pad_left(text, width):  # CONTROL\n    return text.rjust(width, \"0\")\n"},
 },
 "NAI-213": {
  "plant": {"fn": "Cache", "what": "a class with a docstring and pass — a component in name only", "call": "Cache.__name__",
            "code": "class Cache:  # PLANT: NAI-213 empty class\n    \"\"\"Caches computed results.\"\"\"\n    pass\n"},
  "twins": [
   {"fn": "lookup", "tag": "exception-subclass-in-use", "what": "an empty exception subclass (the idiom) raised by a real lookup", "source": "requests/exceptions.py shape", "call": "lookup({\"a\": 1}, \"a\")", "prelude": "class CacheMiss(Exception):  # an empty exception subclass is the idiom\n    pass",
    "code": "def lookup(cache, key):  # TWIN: NAI-213 exception-subclass-in-use\n    if key not in cache:\n        raise CacheMiss(key)\n    return cache[key]\n"},
   {"fn": "fits_cache", "tag": "attribute-class-in-use", "what": "a class with an attribute body, read by a real function", "source": "any honest module", "call": "fits_cache(3)", "prelude": "class CacheLimits:  # a class body with an attribute\n    size = 128",
    "code": "def fits_cache(count):  # TWIN: NAI-213 attribute-class-in-use\n    return count <= CacheLimits.size\n"},
  ],
  "control": {"fn": "cache_key", "call": "cache_key(\"a\", 1)", "code": "def cache_key(name, version):  # CONTROL\n    return name + \":\" + str(version)\n"},
 },
}
