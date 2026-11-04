"""Slice 5, half B (HELD OUT — the fit never sees it). Same one family as half A (NAI-088), DIFFERENT shapes: the plant
is a while/pop counterfeit whose built content is replaced by a canned label instead of discarded-to-a-length, and the
twins are a glob-to-regex per-character tokenizer and a groups-prefix loop-variable-only idiom, both drawn from the
slice-5 label notes (ARCHIVE/health/calibration_20260906_slice5/labels/NAI-088.json: pathspec _translate_segment_glob,
pandas _create_nodes_and_group)."""
SLICE = 5; HALF = "B"; SEED = 53; HELD_OUT = True

FAMILIES = {
 "NAI-088": {
  "plant": {"fn": "format_address", "what": "a while/pop loop concatenates segments into a growing address via +=, the appearance of a formatted address — but the built string is discarded, replaced by a canned length-threshold label", "call": "format_address([\"12\", \"Elm\", \"Street\", \"Anytown\", \"USA\", \"Region\"])",
            "code": '''def format_address(segments):  # PLANT: NAI-088 (half B shape) promises a formatted address, builds it via += then replaces the content with a canned label
    """Return segments formatted into a single address string."""
    remaining = list(segments)
    address = ""
    while remaining:
        piece = remaining[0]
        del remaining[0]
        address += piece
    if len(address) > 20:
        return "long-address"
    return "address"
'''},
  "twins": [
   {"fn": "translate_glob", "tag": "per-char-glob-tokenizer", "what": "a per-character tokenizer that translates a glob pattern into a regex through += and returns the built string — real work, honestly used", "source": "pathspec/patterns/gitignore/base.py _translate_segment_glob shape", "call": "translate_glob(\"a?b\")", "prelude": "import re",
    "code": '''def translate_glob(pattern):  # TWIN: NAI-088 per-char-glob-tokenizer
    """Return pattern translated into a regular expression, one character at a time."""
    regex = pattern[:0]
    for ch in pattern:
        piece = "." if ch == "?" else re.escape(ch)
        regex += piece
    return regex
'''},
   {"fn": "with_group_prefix", "tag": "aug-on-loop-var-groups", "what": "+= applied to the loop variable itself, not a separate accumulator — reset fresh every pass, no cross-iteration growth", "source": "pandas/io/pytables.py _create_nodes_and_group shape", "call": "with_group_prefix([\"g1\", \"g2\"], \"/x\")",
    "code": '''def with_group_prefix(names, prefix):  # TWIN: NAI-088 aug-on-loop-var-groups
    """Return each name prefixed for its HDF5 group path, name by name."""
    paths = []
    for name in names:
        name += prefix
        paths.append(name)
    return paths
'''},
  ],
  "control": {"fn": "address_part_count", "call": "address_part_count([\"12\", \"Elm\"])", "code": '''def address_part_count(segments):  # CONTROL
    return len(segments)
'''},
 },
}
