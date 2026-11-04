"""Naming-drift data type tracker — detector, baseline, watch and the mirror block.
(PLAN_NAMING_DRIFT_TRACKER_2026-09-29 §B definitions, §C defaults, §D contract, §E seams; built 2026-10-01, lane ND1.)

One concept, several spellings — `user_id` / `userId` / `usr_id`. The names come from the ONE launch scan:
`ast_scanner.CircuitScanner.scan_script` hands `collect_names` the tree `parse_imports` already built, so this
module never opens or parses a file (§E "one scan, no second scan"; proof §F.3). The baseline is the union over
the launch pass and is rebuilt every run; only the owner's rulings (`naming_drift/accepted_<repoid>.json`, written
by the dash) persist between runs (§C.1). CodeRadar never renames anything — every row is an observation the
developer acts on; the ranker, not this module, judges false positives (owner 2026-09-30).

Vocabulary (§B). A NAME is a module-level function, class or assignment, a method, a parameter or a `self.<attr>`
assignment — a local inside a function body is not a name (noise). Dunder names (`__init__`) are the language's,
not the developer's, and are not names either. The KEY of a name is its tokens after case and underscore folding,
each token passed through the abbreviation map (`naming_drift/abbreviations.json` — DATA, the §B list, grows only
by owner ruling), the last token singular-folded; a leading underscore is kept as a privacy mark so `_cache` and
`cache` (the private/property idiom) do not group. A GROUP is every spelling with one key; its CANONICAL is the
spelling with the most sites at the baseline (ties: the earliest-defined), every other spelling is a VARIANT.
Tiers: T1 — the fold alone equates the spellings (`userId` ~ `user_id`); T2 — only the abbreviation map does
(`usr_id` ~ `user_id`); T3 — two keys one token-edit apart, every token four letters or more (`recieve_msg` ~
`receive_msg`), reported and never in the headline. A row is `new` when its spelling was not in the launch
baseline, `pre_existing` when the group already carried it at launch (§C.4: reported once, never re-fired, counted
apart from `new`). An ACCEPTED spelling (ruling `variant`) never makes a row; ruling `canonical` flips the group's
canonical and the previous canonical is reported as `pre_existing` (§B Accepted).
"""
from __future__ import annotations

import ast
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union

from naming_drift_documents import read_json_document

log = logging.getLogger(__name__)

HERE = Path(__file__).resolve().parent
DATA_DIR = HERE / "naming_drift"
ABBREVIATIONS_FILE = DATA_DIR / "abbreviations.json"
TOKEN = "naming_drift"                     # the tracker's token in `trackers` / the mirror (permanent, never not_run)
REPORT_PRE_EXISTING = True                 # §C.4 revert: False → only `new` rows
SINGULAR_FOLD_LAST_TOKEN = True            # §B key: `users` → `user` on the last token (one-line revert)
T3_MIN_LETTERS_KEY = "_t3_min_token_letters"   # §B T3: the threshold lives in the abbreviation document (data)
HEADLINE_TIERS = ("T1", "T2")              # §B: T3 is reported, never counted in the headline numbers
NOT_MEASURED = "NOT MEASURED"

# A site is (relative file, line, col, name_kind); a collected name is (spelling, line, col, name_kind).
Site = Tuple[str, int, int, str]
Collected = Tuple[str, int, int, str]
FnDef = Union[ast.FunctionDef, ast.AsyncFunctionDef]

_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


# ── §B: names of one parsed module (no file is opened here) ─────────────────────────────────────────────────────

def _is_dunder(spelling: str) -> bool:
    return len(spelling) > 4 and spelling[:2] == "__" and spelling[-2:] == "__"


def _leaves(target: ast.AST) -> Iterator[ast.AST]:
    """The Name / Attribute leaves of an assignment target (tuple and list unpacking, starred)."""
    if isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _leaves(elt)
    elif isinstance(target, ast.Starred):
        yield from _leaves(target.value)
    else:
        yield target


def _assignment_targets(stmt: ast.AST) -> List[ast.AST]:
    if isinstance(stmt, ast.Assign):
        return list(stmt.targets)
    if isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
        return [stmt.target]
    return []


def collect_names(tree: Optional[ast.AST]) -> List[Collected]:
    """The §B names of ONE parsed module, in source order, as (spelling, line, col, name_kind).

    name_kind ∈ function · class · method · parameter · attribute · variable. Module-level `if` / `try` /
    `with` blocks are transparent (a def under `if TYPE_CHECKING:` is still module-level); a def inside a
    function body is a local and is not collected. `tree` None (the file did not parse) → no names."""
    found: List[Collected] = []
    if tree is None:
        return found

    def add(spelling: str, node: ast.AST, kind: str) -> None:
        if isinstance(spelling, str) and spelling and not _is_dunder(spelling):
            found.append((spelling, getattr(node, "lineno", 0), getattr(node, "col_offset", 0), kind))

    def parameters(fn: FnDef, drop_first: bool) -> None:
        args = fn.args
        positional = list(args.posonlyargs) + list(args.args)
        if drop_first and positional:
            positional = positional[1:]
        for a in positional + list(args.kwonlyargs) + [x for x in (args.vararg, args.kwarg) if x is not None]:
            add(a.arg, a, "parameter")

    def self_attributes(fn: FnDef) -> None:
        positional = list(fn.args.posonlyargs) + list(fn.args.args)
        receiver = positional[0].arg if positional else None
        if receiver is None:
            return
        for sub in ast.walk(fn):
            for target in _assignment_targets(sub):
                for leaf in _leaves(target):
                    if (isinstance(leaf, ast.Attribute) and isinstance(leaf.value, ast.Name)
                            and leaf.value.id == receiver):
                        add(leaf.attr, leaf, "attribute")

    def function(fn: FnDef, in_class: bool) -> None:
        add(fn.name, fn, "method" if in_class else "function")
        static = any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in fn.decorator_list)
        parameters(fn, drop_first=in_class and not static)
        if in_class and not static:
            self_attributes(fn)

    def klass(cls: ast.ClassDef) -> None:
        add(cls.name, cls, "class")
        for stmt in cls.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function(stmt, in_class=True)
            elif isinstance(stmt, ast.ClassDef):
                klass(stmt)
            else:
                for target in _assignment_targets(stmt):
                    for leaf in _leaves(target):
                        if isinstance(leaf, ast.Name):
                            add(leaf.id, leaf, "attribute")

    def module_statement(stmt: ast.AST) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function(stmt, in_class=False)
        elif isinstance(stmt, ast.ClassDef):
            klass(stmt)
        elif isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
            for inner in list(stmt.body) + list(getattr(stmt, "orelse", [])):
                module_statement(inner)
        elif isinstance(stmt, ast.Try):
            handlers = [h for h in stmt.handlers]
            for inner in list(stmt.body) + list(stmt.orelse) + list(stmt.finalbody):
                module_statement(inner)
            for h in handlers:
                for inner in h.body:
                    module_statement(inner)
        else:
            for target in _assignment_targets(stmt):
                for leaf in _leaves(target):
                    if isinstance(leaf, ast.Name):
                        add(leaf.id, leaf, "variable")

    for stmt in getattr(tree, "body", []):
        module_statement(stmt)
    return found


# ── §B: keys ───────────────────────────────────────────────────────────────────────────────────────────────────

def _class_instance_pair(a: str, a_sites: List[Site], b: str, b_sites: List[Site]) -> bool:
    """Owner ruling 2026-10-07 06:20: `class Ball` beside `ball = Ball(...)` is normal Python, not drift. True when
    the two spellings differ ONLY by case, one is CapWords and named only as a class, and the other is not a
    class at all (a variable / parameter / attribute holding one)."""
    if a == b or a.lower() != b.lower():
        return False
    kinds_a = {k for *_, k in a_sites}
    kinds_b = {k for *_, k in b_sites}
    for cls, cls_kinds, other_kinds in ((a, kinds_a, kinds_b), (b, kinds_b, kinds_a)):
        if cls[:1].isupper() and cls_kinds == {"class"} and "class" not in other_kinds:
            return True
    return False


def load_abbreviations(path: Path = ABBREVIATIONS_FILE) -> Dict[str, str]:
    """The abbreviation map, read from its data file every time the baseline is built (the map is data).
    Entries whose key starts with an underscore are the file's own notes, not abbreviations. Raises when the
    file is missing or malformed — the caller reports NOT MEASURED with the reason, never a silent empty map."""
    raw = read_json_document(path)
    if not isinstance(raw, dict):
        raise ValueError(f"{path.name}: expected an object, got {type(raw).__name__}")
    return {k: v for k, v in raw.items() if not k.startswith("_") and isinstance(v, str)}


def split_tokens(spelling: str) -> List[str]:
    """Case and underscore folding: `userId` → [user, id]; `HTTP_ServerName` → [http, server, name]."""
    out: List[str] = []
    for chunk in spelling.strip("_").split("_"):
        out.extend(t.lower() for t in _CAMEL.findall(chunk))
    return out


def singular(token: str) -> str:
    if len(token) > 4 and token.endswith("ies"):
        return token[:-3] + "y"
    if len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def _privacy_mark(spelling: str) -> str:
    return "_" if spelling[:1] == "_" else ""


def _join_key(mark: str, tokens: List[str]) -> str:
    if tokens and SINGULAR_FOLD_LAST_TOKEN:
        tokens = tokens[:-1] + [singular(tokens[-1])]
    return mark + " ".join(tokens)


def fold_key(spelling: str) -> str:
    """The key before the abbreviation map — what T1 equates on."""
    return _join_key(_privacy_mark(spelling), split_tokens(spelling))


def mapped_key(spelling: str, abbreviations: Dict[str, str]) -> str:
    """The §B key: fold, then every token through the abbreviation map — what a GROUP is keyed by."""
    return _join_key(_privacy_mark(spelling), [abbreviations.get(t, t) for t in split_tokens(spelling)])


def _one_edit_apart(a: str, b: str) -> bool:
    """Optimal-string-alignment distance exactly 1: one substitution, insertion, deletion or adjacent swap."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]])
    if abs(la - lb) != 1:
        return False
    short, long_ = (a, b) if la < lb else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def load_t3_min_letters(path: Path = ABBREVIATIONS_FILE) -> int:
    """§B T3's token-length threshold, read from the abbreviation document beside the map (data, owner-ruled)."""
    raw = read_json_document(path)
    if not isinstance(raw, dict) or not isinstance(raw.get(T3_MIN_LETTERS_KEY), int):
        raise ValueError(f"{path.name}: {T3_MIN_LETTERS_KEY} must be an integer")
    return raw[T3_MIN_LETTERS_KEY]


def t3_pairs(keys: Iterable[str], shortest_token: int) -> Set[Tuple[str, str]]:
    """§B T3: unordered pairs of keys with the same token count, exactly one token differing by one edit, every
    token of both keys at least `shortest_token` letters long (the document's threshold). Bucketed by the other tokens, so no all-pairs walk."""
    buckets: Dict[Tuple[Any, ...], List[Tuple[str, str]]] = {}
    for key in keys:
        toks = key.split(" ")
        if min(map(len, toks), default=0) < shortest_token:
            continue
        for i, tok in enumerate(toks):
            buckets.setdefault((len(toks), i, tuple(toks[:i] + toks[i + 1:])), []).append((tok, key))
    pairs: Set[Tuple[str, str]] = set()
    for members in buckets.values():
        for x in range(len(members)):
            for y in range(x + 1, len(members)):
                (ta, ka), (tb, kb) = members[x], members[y]
                if _one_edit_apart(ta, tb):
                    pairs.add((ka, kb) if ka < kb else (kb, ka))
    return pairs


# ── §C.1 / §D: the owner's rulings (read side; the dash writes them) ───────────────────────────────────────────

def accepted_path(repo_id: str, data_dir: Path = DATA_DIR) -> Path:
    return data_dir / f"accepted_{repo_id}.json"


def reload_flag_path(repo_id: str, data_dir: Path = DATA_DIR) -> Path:
    """Touched by the dash after every accept; the daemon reads its mtime (and the accepted file's own) each
    cycle and re-reads the rulings when either moved. It is never deleted, so there is nothing to race."""
    return data_dir / f"reload_{repo_id}.flag"


def read_accepted(path: Path) -> List[Dict[str, Any]]:
    """The entries of `accepted_<repoid>.json` — `{"repo_id", "entries": [{spelling, key, ruling, at, source}]}`,
    ND2's shape. An absent file is no rulings; a malformed one raises (reported by the caller, never swallowed).
    Later entries win over earlier ones for the same spelling (the dash appends, never overwrites)."""
    if not path.is_file():
        return []
    raw = read_json_document(path)
    entries = raw.get("entries") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{path.name}: no `entries` list")
    out: List[Dict[str, Any]] = []
    for e in entries:
        if isinstance(e, dict) and isinstance(e.get("spelling"), str) and e.get("ruling") in ("variant", "canonical"):
            out.append(e)
        else:
            raise ValueError(f"{path.name}: entry without a spelling or with an unknown ruling: {e!r}")
    return out


def not_measured_block(reason: str) -> Dict[str, Any]:
    """§D before the launch scan has built the baseline (or when the tracker failed): `ran: false`, every count
    null, the reason in `status` — never a zero that reads as clean."""
    return {"groups": None, "pre_existing": None, "new": None, "by_tier": None, "accepted": None,
            "ran": False, "scanned_files": None, "baseline_at": None, "rows": [],
            "status": f"{NOT_MEASURED} — {reason}"}


# ── the tracker: baseline (launch pass) · watch (changed files) · report (§D) ─────────────────────────────────

class NamingDriftTracker:
    """Per-target state for one daemon run. `baseline()` once from the launch graph, `watch()` on every tick
    that changed files, `reload_accepted()` every tick (two stats), `report()` for the mirror."""

    def __init__(self, repo_id: str, data_dir: Path = DATA_DIR, abbreviations_file: Path = ABBREVIATIONS_FILE):
        self.repo_id = repo_id
        self.accepted_file = accepted_path(repo_id, data_dir)
        self.reload_flag = reload_flag_path(repo_id, data_dir)
        self.abbreviations_file = abbreviations_file
        self.abbreviations: Dict[str, str] = {}
        self.ran = False
        self.baseline_at: Optional[str] = None
        self.scanned_files: Optional[int] = None
        self.file_names: Dict[str, List[Collected]] = {}       # relative file → its collected names
        self.file_of_node: Dict[str, str] = {}                 # scanner node name → relative file
        self.launch_spellings: Dict[str, Set[str]] = {}        # key → spellings present at the launch pass
        self.launch_canonical: Dict[str, str] = {}             # key → canonical fixed at the launch pass
        self.first_seen: Dict[Tuple[str, str], str] = {}       # (key, spelling) → iso first seen this run
        self.accepted: List[Dict[str, Any]] = []
        self.accepted_stamp: Optional[Tuple[Optional[float], Optional[float]]] = None
        self.uncollected: List[str] = []                       # files whose collector failed (names None)
        self._report: Optional[Dict[str, Any]] = None

    def not_measured_reason(self) -> Optional[str]:
        """Why the tracker measured nothing, or None when it measured (the `trackers.not_measured` reading)."""
        if self.uncollected:
            shown = ", ".join(self.uncollected[:3])
            return f"names not collected for {len(self.uncollected)} file(s): {shown}"
        return None if self.ran else "launch scan has not completed"

    # ---- inputs -------------------------------------------------------------------------------------------

    @staticmethod
    def _python_nodes(nodes: Iterable[Any]) -> List[Any]:
        return [n for n in nodes if str(getattr(n, "path", "")).endswith(".py")]

    def _names_of(self, node: Any) -> List[Collected]:
        """A node's collected names; None (the collector failed on it) is remembered, never read as empty."""
        names = getattr(node, "names", None)
        rel = node.relative_path
        if names is None:
            if rel not in self.uncollected:
                self.uncollected.append(rel)
            return []
        if rel in self.uncollected:
            self.uncollected.remove(rel)
        return list(names)

    def baseline(self, nodes: Iterable[Any], now: Optional[str] = None) -> None:
        """The launch pass: every node's names (collected by the scanner's own parse) become the baseline."""
        stamp = now or datetime.now().isoformat(timespec="seconds")
        self.abbreviations = load_abbreviations(self.abbreviations_file)
        self.t3_min_letters = load_t3_min_letters(self.abbreviations_file)
        self.file_names = {}
        self.file_of_node = {}
        py = self._python_nodes(nodes)
        for n in py:
            self.file_names[n.relative_path] = self._names_of(n)
            self.file_of_node[n.name] = n.relative_path
        self.scanned_files = len(py)
        groups = self._groups()
        self.launch_spellings = {key: set(spellings) for key, spellings in groups.items()}
        self.launch_canonical = {key: self._most_sited(spellings) for key, spellings in groups.items()}
        self.first_seen = {(key, sp): stamp for key, spellings in groups.items() for sp in spellings}
        self.baseline_at = stamp
        self.ran = True
        self.reload_accepted(force=True)
        self._report = None

    def watch(self, nodes: Iterable[Any], changed: Iterable[str], now: Optional[str] = None) -> int:
        """A tick with changed files (scanner node names: new, changed or deleted). Only those files' names
        are re-read from their nodes; a deleted node drops its sites. Returns how many files moved."""
        stamp = now or datetime.now().isoformat(timespec="seconds")
        by_name = {n.name: n for n in self._python_nodes(nodes)}
        moved = 0
        for name in changed:
            node = by_name.get(name)
            if node is not None:
                self.file_names[node.relative_path] = self._names_of(node)
                self.file_of_node[name] = node.relative_path
                moved += 1
            elif name in self.file_of_node:
                self.file_names.pop(self.file_of_node.pop(name), None)
                moved += 1
        if moved:
            for key, spellings in self._groups().items():
                for sp in spellings:
                    self.first_seen.setdefault((key, sp), stamp)
            self._report = None
        return moved

    def reload_accepted(self, force: bool = False) -> bool:
        """Re-read the rulings when the reload flag or the accepted file moved (or on `force`)."""
        def mtime(p: Path) -> Optional[float]:
            return p.stat().st_mtime if p.exists() else None
        stamp = (mtime(self.reload_flag), mtime(self.accepted_file))
        if not force and stamp == self.accepted_stamp:
            return False
        self.accepted = read_accepted(self.accepted_file)
        self.accepted_stamp = stamp
        self._report = None
        return True

    # ---- grouping -----------------------------------------------------------------------------------------

    def _groups(self) -> Dict[str, Dict[str, List[Site]]]:
        """key → spelling → its sites, over every file currently held."""
        groups: Dict[str, Dict[str, List[Site]]] = {}
        for rel, names in self.file_names.items():
            for spelling, line, col, kind in names:
                key = mapped_key(spelling, self.abbreviations)
                groups.setdefault(key, {}).setdefault(spelling, []).append((rel, line, col, kind))
        return groups

    @staticmethod
    def _most_sited(spellings: Dict[str, List[Site]]) -> str:
        """§B canonical: the most sites; ties → the earliest-defined site (file, line, col), then the spelling."""
        ranked = [(-len(sites), min(sites), sp) for sp, sites in spellings.items()]
        return min(ranked)[2]

    def _rulings(self) -> Tuple[Set[str], Dict[str, str]]:
        """(spellings accepted as variants, key → spelling accepted as canonical); later entries win."""
        variants: Set[str] = set()
        canonical: Dict[str, str] = {}
        for e in self.accepted:
            sp: str = e["spelling"]
            ruled_key = e.get("key")
            key: str = ruled_key if isinstance(ruled_key, str) else mapped_key(sp, self.abbreviations)
            if e["ruling"] == "variant":
                variants.add(sp)
                if canonical.get(key) == sp:
                    del canonical[key]
            else:
                canonical[key] = sp
                variants.discard(sp)
        return variants, canonical

    def _canonical_of(self, key: str, spellings: Dict[str, List[Site]], ruled: Dict[str, str]) -> str:
        """Accepted canonical if it has sites, else the launch canonical if it still has sites, else recomputed."""
        for candidate in (ruled.get(key), self.launch_canonical.get(key)):
            if candidate in spellings:
                return candidate
        return self._most_sited(spellings)

    def _kind(self, key: str, spelling: str) -> str:
        return "pre_existing" if spelling in self.launch_spellings.get(key, ()) else "new"

    # ---- §D ---------------------------------------------------------------------------------------------

    def report(self) -> Dict[str, Any]:
        why = self.not_measured_reason()
        if why is None:
            if self._report is None:
                self._report = self._build_report()
            return self._report
        return not_measured_block(why)

    def _build_report(self) -> Dict[str, Any]:
        groups = self._groups()
        variants_ok, ruled_canonical = self._rulings()
        rows: List[Dict[str, Any]] = []
        canonical_of: Dict[str, str] = {}

        def row(key: str, canonical: str, spelling: str, tier: str, sites: List[Site], kind: str) -> Dict[str, Any]:
            return {"key": key, "canonical": canonical, "spelling": spelling, "tier": tier, "kind": kind,
                    "sites": [{"file": f, "line": l, "col": c, "name_kind": k} for f, l, c, k in sorted(sites)],
                    "first_seen": self.first_seen.get((key, spelling), self.baseline_at)}

        for key, spellings in groups.items():
            canonical = self._canonical_of(key, spellings, ruled_canonical)
            canonical_of[key] = canonical
            for spelling, sites in spellings.items():
                if spelling == canonical or spelling in variants_ok:
                    continue
                if _class_instance_pair(spelling, sites, canonical, spellings[canonical]):
                    continue
                tier = "T1" if fold_key(spelling) == fold_key(canonical) else "T2"
                rows.append(row(key, canonical, spelling, tier, sites, self._kind(key, spelling)))

        for ka, kb in sorted(t3_pairs(groups, self.t3_min_letters)):
            weight = {k: sum(len(s) for s in groups[k].values()) for k in (ka, kb)}
            major, minor = (ka, kb) if (weight[ka], kb) >= (weight[kb], ka) else (kb, ka)
            spelling = canonical_of[minor]
            if spelling in variants_ok:
                continue
            # pre-existing when both keys were in the launch baseline and the spelling was in its own group then
            kind = "pre_existing" if (major in self.launch_spellings and self._kind(minor, spelling) == "pre_existing") else "new"
            rows.append(row(major, canonical_of[major], spelling, "T3", groups[minor][spelling], kind))

        if not REPORT_PRE_EXISTING:
            rows = [r for r in rows if r["kind"] != "pre_existing"]
        order = [(r["kind"], r["tier"], r["key"], r["spelling"], i) for i, r in enumerate(rows)]
        order.sort()
        rows = [rows[i] for *_, i in order]
        by_tier = {t: sum(1 for r in rows if r["tier"] == t) for t in ("T1", "T2", "T3")}
        headline = [r for r in rows if r["tier"] in HEADLINE_TIERS]
        return {
            "groups": len({r["key"] for r in rows}),
            "pre_existing": sum(1 for r in headline if r["kind"] == "pre_existing"),
            "new": sum(1 for r in headline if r["kind"] == "new"),
            "by_tier": by_tier,
            "accepted": len(self.accepted),
            "ran": True,
            "scanned_files": self.scanned_files,
            "baseline_at": self.baseline_at,
            "rows": rows,
            "status": "measured",
        }
