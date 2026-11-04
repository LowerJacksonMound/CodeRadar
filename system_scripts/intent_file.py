"""The INTENT FILE — one per target: `system_scripts/intent_<repoid>.json` (Item 8, 2026-09-15).

Where the developer's statement and every intent-bearing source meet. Writers: the whitelist stage (launch S1 —
the artifact scanner's intent-source facts, Item 3), the dashboard (the Purpose field — the statement, labelled
`developer`), the Builder cycle (FIX_33 step 3 — `doc_mention` facts from the context manager, source `doc_mention`;
Item 9 — facts from the tester's failure logs, source `tester`). Readers: the Ranker's `ProjectProfile` (`knowledge_base._analyze_repo`), the path-hack
detector's declared-dependency set (FIX_16 step 3), the NOAI daemon's `summary.intent`.

Dependency-free (`scan_scope.py` style). Every read-modify-write runs under `fcntl.flock` on `.intent_<repoid>.lock`
— three writers. The statement is AUTHORED, never scanned: it is never cleared by a relaunch (launch.sh's pre-flight
archives other targets' intent files and keeps the current target's); `replace_source_facts` replaces only the facts
whose source is one of the named intent-source species, so a rescan refreshes what a scan found and nothing else.

Owner-confirmed 2026-09-15 (RULINGS_NEEDED A3): the statement is turned into DISCRETE facts by FIXED rules — keyword
tables, no LLM; five fact kinds (domain, entry_point, expected_input / expected_output, runner, external_system —
plus framework from the packaging list); English-only tables; a fact is ABSENT, never wrong, when nothing matches;
absent facts fill in through the process (intent sources, tester logs). `evidence` is the matched span.

File shape: {target, repo_id, generated_at, statement: {text, source, submitted_at} | null,
             facts: [{fact, value, source, evidence, recorded_at}]}
"""
from __future__ import annotations

import ast
import fcntl
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

SCRIPTS_DIR = Path(__file__).resolve().parent

# The intent-source species of SPECIES_DICT.intent_sources (Item 3) — the sources `replace_source_facts` refreshes
# on every whitelist stage; every other source (developer, doc_mention, tester) is append-only. I-22 (run 117,
# 2026-09-15): `docs` here is the SPECIES (the docs directory's facts) — the Builder's doc_mention facts carry the
# source `doc_mention` so a relaunch never wipes them.
INTENT_SOURCE_SPECIES: Tuple[str, ...] = (
    "ci_workflow", "lint_config", "type_config", "packaging", "docs", "readme", "changelog", "contributing",
    "pre_commit", "tox",
)

# ── fixed extractor tables (English; owner-confirmed 2026-09-15) ────────────────────────────────────────────
DOMAIN_TABLE: Dict[str, Tuple[str, ...]] = {
    "cli": ("command line", "command-line", "cli", "terminal", "console", "shell tool"),
    "web_service": ("web service", "web app", "web application", "http", "rest", "api server", "website",
                    "endpoint", "microservice"),
    "library": ("library", "package", "sdk", "toolkit", "module for", "helper for"),
    "data_pipeline": ("pipeline", "etl", "batch job", "data processing", "ingest", "data flow"),
    "gui": ("gui", "desktop app", "desktop application", "window", "tkinter", "qt ", "pyqt", "wx"),
    "bot": ("bot", "chatbot", "chat bot"),
    "daemon": ("daemon", "background service", "service that runs", "watcher", "long-running", "scheduler"),
}
FORMAT_TOKENS: Tuple[str, ...] = ("json", "csv", "yaml", "yml", "xml", "sqlite", "parquet", "html", "pdf",
                                  "stdin", "stdout", "toml", "ini", "excel", "xlsx", "markdown", "png", "jpeg")
INPUT_VERBS: Tuple[str, ...] = ("reads", "read", "takes", "take", "accepts", "accept", "consumes", "consume",
                                "parses", "parse", "loads", "load", "ingests", "ingest", "receives", "receive",
                                "imports", "import")
OUTPUT_VERBS: Tuple[str, ...] = ("writes", "write", "produces", "produce", "outputs", "output", "returns",
                                 "return", "emits", "emit", "generates", "generate", "saves", "save", "exports",
                                 "export", "prints", "print", "renders", "render")
RUNNER_TABLE: Tuple[str, ...] = ("pytest", "unittest", "tox", "nox", "make test")
EXTERNAL_SYSTEMS: Tuple[str, ...] = ("postgres", "postgresql", "mysql", "mariadb", "sqlite", "redis", "kafka",
                                     "rabbitmq", "s3", "aws", "gcp", "azure", "docker", "kubernetes", "slack",
                                     "discord", "telegram", "github", "gitlab", "stripe", "twilio",
                                     "elasticsearch", "mongodb", "snowflake", "bigquery")
FRAMEWORKS: Tuple[str, ...] = ("django", "flask", "fastapi", "sqlalchemy", "pydantic",   # _parse_pyproject's list minus pytest (a runner, RUNNER_TABLE)
                               "click", "typer", "numpy", "pandas", "torch", "aiohttp")

_WORD = re.compile(r"[a-z][a-z0-9_]*")


# ── the file ─────────────────────────────────────────────────────────────────────────────────────────────────

def repo_id(target: Path | str) -> str:
    """Same scheme as circuit_daemon.get_repo_id / launch.sh / scan_scope.repo_id: sha256(resolved)[:12]."""
    return hashlib.sha256(str(Path(target).resolve()).encode()).hexdigest()[:12]


def path(target: Path | str) -> Path:
    return SCRIPTS_DIR / f"intent_{repo_id(target)}.json"


def _lock_path(target: Path | str) -> Path:
    return SCRIPTS_DIR / f".intent_{repo_id(target)}.lock"


def _empty(target: Path | str) -> dict:
    return {"target": str(Path(target).resolve()), "repo_id": repo_id(target),
            "generated_at": datetime.now(timezone.utc).isoformat(), "statement": None, "facts": []}


def _load(target: Path | str) -> dict:
    p = path(target)
    if not p.exists():
        return _empty(target)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _empty(target)
    if not isinstance(data, dict):
        return _empty(target)
    data.setdefault("target", str(Path(target).resolve()))
    data.setdefault("repo_id", repo_id(target))
    data.setdefault("statement", None)
    data.setdefault("facts", [])
    return data


def read(target: Path | str) -> dict:
    """The intent file as it stands (an empty structure when there is none) — never creates the file."""
    return _load(target)


class _locked:
    def __init__(self, target: Path | str) -> None:
        self._p = _lock_path(target)
        self._fh = None

    def __enter__(self) -> "_locked":
        self._fh = open(self._p, "a+")  # type: ignore[assignment]  # FIX_54 ast-pos
        fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)  # type: ignore[attr-defined]  # FIX_54 ast-pos
        return self

    def __exit__(self, *exc: object) -> None:
        assert self._fh is not None
        fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        self._fh.close()


def _write(target: Path | str, data: dict) -> Path:
    data["generated_at"] = datetime.now(timezone.utc).isoformat()
    p = path(target)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, p)
    return p


def _fact(fact: str, value: str, source: str, evidence: str) -> dict:
    return {"fact": fact, "value": value, "source": source, "evidence": evidence,
            "recorded_at": datetime.now(timezone.utc).isoformat()}


def _norm_facts(facts: Iterable[dict]) -> List[dict]:
    out: List[dict] = []
    for f in facts or []:
        if not isinstance(f, dict) or not f.get("fact") or f.get("value") is None or not f.get("source"):
            continue
        out.append(_fact(str(f["fact"]), str(f["value"]), str(f["source"]), str(f.get("evidence", "") or "")))
    return out


def set_statement(target: Path | str, text: str, source: str = "developer") -> dict:
    """The developer's statement — authored, labelled, never cleared by a scan."""
    with _locked(target):
        data = _load(target)
        text = (text or "").strip()
        data["statement"] = ({"text": text, "source": source, "submitted_at": datetime.now(timezone.utc).isoformat()}
                             if text else None)
        _write(target, data)
    return data


def replace_source_facts(target: Path | str, facts: Iterable[dict], sources: Sequence[str] = INTENT_SOURCE_SPECIES) -> dict:
    """Replace every fact whose source is one of `sources` with `facts` (the scan's fresh reading); every other
    fact — the developer's, the doc_mention facts, the tester's — stays."""
    srcs = set(sources)
    with _locked(target):
        data = _load(target)
        kept = [f for f in data["facts"] if f.get("source") not in srcs]
        data["facts"] = kept + [f for f in _norm_facts(facts) if f["source"] in srcs]
        _write(target, data)
    return data


def append_facts(target: Path | str, facts: Iterable[dict]) -> Tuple[dict, int]:
    """Append facts, deduplicated on (fact, value, source). Returns (file, number actually added)."""
    with _locked(target):
        data = _load(target)
        seen = {(f.get("fact"), f.get("value"), f.get("source")) for f in data["facts"]}
        added = 0
        for f in _norm_facts(facts):
            key = (f["fact"], f["value"], f["source"])
            if key in seen:
                continue
            seen.add(key)
            data["facts"].append(f)
            added += 1
        if added:
            _write(target, data)
    return data, added


def facts_by_source(data: dict) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in data.get("facts") or []:
        out[f.get("source", "?")] = out.get(f.get("source", "?"), 0) + 1
    return dict(sorted(out.items()))


def facts_of(data: dict, fact: str, sources: Optional[Iterable[str]] = None) -> List[str]:
    """Values of one fact kind, in file order, deduplicated (optionally restricted to sources)."""
    srcs = set(sources) if sources is not None else None
    out: List[str] = []
    for f in data.get("facts") or []:
        if f.get("fact") == fact and (srcs is None or f.get("source") in srcs) and f.get("value") not in out:
            out.append(f["value"])
    return out


# ── the statement extractor (fixed rules) ────────────────────────────────────────────────────────────────────

def target_names(target: Path | str) -> Set[str]:
    """Module names and top-level def / class names of the target's live .py files — the corroboration set for
    `entry_point` (the ONE walk: scan_scope.iter_live_py; a plain contained glob when scan_scope is unavailable)."""
    root = Path(target).resolve()
    names: Set[str] = set()
    try:
        import scan_scope  # type: ignore
        files = list(scan_scope.iter_live_py(root))
    except Exception:
        files = [p for p in root.rglob("*.py") if not p.is_symlink()
                 and not any(part.startswith(".") for part in p.relative_to(root).parts)]
    for p in files:
        rel = p.relative_to(root)
        names.add(rel.stem)
        if rel.stem in ("__init__", "__main__") and rel.parent != Path("."):
            names.add(rel.parent.name)
        names.update(part for part in rel.parts[:-1])
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError, OSError):
            continue
        names.update(n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    return names


def _clauses(text: str) -> List[str]:
    return [c.strip() for c in re.split(r"[;.\n]|\bthen\b|\band then\b", text) if c.strip()]


def _io_facts(text: str, source: str) -> List[dict]:
    """expected_input / expected_output: a format token in the clause after an input verb vs an output verb.
    Inside one clause the verb nearest BEFORE the token decides its side."""
    out: List[dict] = []
    for clause in _clauses(text):
        low = clause.lower()
        verbs: List[Tuple[int, str]] = []
        for v in INPUT_VERBS:
            for m in re.finditer(r"\b" + re.escape(v) + r"\b", low):
                verbs.append((m.start(), "expected_input"))
        for v in OUTPUT_VERBS:
            for m in re.finditer(r"\b" + re.escape(v) + r"\b", low):
                verbs.append((m.start(), "expected_output"))
        if not verbs:
            continue
        verbs.sort()
        for tok in FORMAT_TOKENS:
            for m in re.finditer(r"\b" + re.escape(tok) + r"\b", low):
                before = [side for pos, side in verbs if pos < m.start()]
                if not before:
                    continue
                side = before[-1]
                vpos = max(pos for pos, _ in verbs if pos < m.start())
                value = "yaml" if tok == "yml" else tok
                out.append(_fact(side, value, source, clause[vpos:m.end()]))
    return out


def extract_statement_facts(text: str, target: Path | str, source: str = "developer") -> List[dict]:
    """Discrete facts from a free-text statement, by the fixed tables above. Absent = no row, never a wrong row."""
    text = (text or "").strip()
    if not text:
        return []
    low = text.lower()
    facts: List[dict] = []
    # domain — every keyword match kept (a tool can be a CLI and a library)
    for domain, words in DOMAIN_TABLE.items():
        for w in words:
            m = re.search(r"(?<![a-z])" + re.escape(w) + r"(?![a-z])", low)
            if m:
                facts.append(_fact("domain", domain, source, text[m.start():m.end()]))
                break
    # entry_point — `python -m X`, `X.py`, or a backticked identifier; CORROBORATED by a target module / def name
    names = target_names(target)
    seen_entries: Set[str] = set()
    candidates: List[Tuple[str, str]] = []
    for m in re.finditer(r"python3?\s+-m\s+([A-Za-z_][\w.]*)", text):
        candidates.append((m.group(1), m.group(0)))
    for m in re.finditer(r"\b([A-Za-z_]\w*)\.py\b", text):
        candidates.append((m.group(1), m.group(0)))
    for m in re.finditer(r"`([A-Za-z_][\w.]*)`", text):
        candidates.append((m.group(1), m.group(0)))
    for ident, span in candidates:
        head = ident.split(".")[0]
        if ident in names or head in names:
            if ident not in seen_entries:
                seen_entries.add(ident)
                facts.append(_fact("entry_point", ident, source, span))
    facts.extend(_io_facts(text, source))
    for r in RUNNER_TABLE:
        m = re.search(r"(?<![a-z])" + re.escape(r) + r"(?![a-z])", low)
        if m:
            facts.append(_fact("runner", r, source, text[m.start():m.end()]))
    for sysname in EXTERNAL_SYSTEMS:
        m = re.search(r"(?<![a-z])" + re.escape(sysname) + r"(?![a-z])", low)
        if m:
            facts.append(_fact("external_system", sysname, source, text[m.start():m.end()]))
    for fw in FRAMEWORKS:
        m = re.search(r"(?<![a-z])" + re.escape(fw) + r"(?![a-z])", low)
        if m:
            facts.append(_fact("framework", fw, source, text[m.start():m.end()]))
    # dedupe on (fact, value)
    uniq: List[dict] = []
    keys: Set[Tuple[str, str]] = set()
    for f in facts:
        k = (f["fact"], f["value"])
        if k not in keys:
            keys.add(k)
            uniq.append(f)
    return uniq


def submit_statement(target: Path | str, text: str) -> Tuple[dict, List[dict]]:
    """The Purpose field's one action: store the statement (developer), extract its facts, append them.
    Returns (file, the facts extracted)."""
    set_statement(target, text, source="developer")
    facts = extract_statement_facts(text, target, source="developer")
    data, _ = append_facts(target, facts)
    return data, facts


# ── Item 9 (2026-09-15): facts from a tester FAILURE LOG (Item 5's return-channel line), source "tester" ────────
_EXC_LINE = re.compile(r"^\s*(?:E\s+)?([A-Za-z_][\w.]*(?:Error|Exception|Warning|Exit))\b\s*:?", re.M)
_FRAME = re.compile(r'^\s*File "([^"]+)", line (\d+), in ([A-Za-z_<][\w>]*)', re.M)
_PYTEST_ASSERT = re.compile(r"^\s*E\s+assert\s+(.+?)\s*==\s*(.+?)\s*$", re.M)
_UNITTEST_ASSERT = re.compile(r"AssertionError:\s*(.+?)\s*!=\s*(.+?)\s*$", re.M)
_TEST_DIRS = frozenset({"test", "tests", "testing"})


def _literal(text: str) -> Optional[str]:
    try:
        return repr(ast.literal_eval(text.strip()))
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return None


def _rel_in_target(path_text: str, root: Path) -> Optional[str]:
    """The frame's path relative to the target root when it lies inside it (by string containment of the
    resolved root, or a relative path that exists under the root); None otherwise."""
    p = Path(path_text)
    try:
        if p.is_absolute():
            rel = p.resolve().relative_to(root.resolve())
            return rel.as_posix()
    except ValueError:
        return None
    if (root / p).exists():
        return p.as_posix()
    return None


def _is_test_species_path(rel: str) -> bool:
    pp = Path(rel)
    return bool({x.lower() for x in pp.parts[:-1]} & _TEST_DIRS) or pp.name.startswith("test_") \
        or pp.name.endswith("_test.py") or pp.name == "conftest.py"


def extract_failure_log_facts(entry: dict, target: Path | str, source: str = "tester") -> List[dict]:
    """Item 9: discrete facts from ONE failed return-channel entry `{digest, failure_log, outcome, …}` — fixed rules,
    no LLM; `evidence` = the solution digest the tester failed (then the matched span). Only `outcome == "failed"`
    entries carry a failure log worth reading; anything else → no fact. Rules (the plan §4): `exception_type` = the
    LAST `<Name>(Error|Exception|Warning|Exit):` line (pytest `E   <Name>:` included); `module_under_test` /
    `function_under_test` = the DEEPEST `File "<p>", line N, in <f>` frame whose path is inside the target and not
    test species; `expected_literal` / `actual_literal` only when both sides of a pytest `E   assert a == b` or an
    unittest `AssertionError: a != b` parse as literals; `runner` = pytest (`test session starts` / `E   ` lines),
    unittest (`FAIL|ERROR: test_x (` / `Ran N tests`), plain (a bare `Traceback`), absent otherwise."""
    if not isinstance(entry, dict) or entry.get("outcome", "failed") != "failed":
        return []
    log = str(entry.get("failure_log") or "")
    digest = str(entry.get("digest") or "")
    if not log.strip() or not digest:
        return []
    root = Path(target).resolve()
    facts: List[dict] = []
    ev = lambda span: f"{digest} | {span.strip()[:100]}"
    excs = list(_EXC_LINE.finditer(log))
    if excs:
        m = excs[-1]
        facts.append(_fact("exception_type", m.group(1).split(".")[-1], source, ev(log[m.start():m.end()])))
    deepest: Optional[Tuple[str, str, str]] = None
    for m in _FRAME.finditer(log):
        rel = _rel_in_target(m.group(1), root)
        if rel and not _is_test_species_path(rel):
            deepest = (rel, m.group(3), log[m.start():m.end()])
    if deepest:
        rel, fn, span = deepest
        facts.append(_fact("module_under_test", rel, source, ev(span)))
        if fn and fn != "<module>":
            facts.append(_fact("function_under_test", f"{rel}::{fn}", source, ev(span)))
    m = _PYTEST_ASSERT.search(log) or _UNITTEST_ASSERT.search(log)  # type: ignore[assignment]  # FIX_54 ast-pos
    if m:
        a, b = _literal(m.group(1)), _literal(m.group(2))
        if a is not None and b is not None:
            if _PYTEST_ASSERT.match(log[m.start():m.end()]):
                actual, expected = a, b          # pytest: `assert <actual> == <expected>`
            else:
                actual, expected = a, b          # unittest: `AssertionError: <first> != <second>`
            facts.append(_fact("expected_literal", expected, source, ev(log[m.start():m.end()])))
            facts.append(_fact("actual_literal", actual, source, ev(log[m.start():m.end()])))
    runner = None
    if "test session starts" in log or re.search(r"^\s*E\s{2,}", log, re.M):
        runner = "pytest"
    elif re.search(r"^(FAIL|ERROR): test_\w+ \(", log, re.M) or re.search(r"^Ran \d+ tests?", log, re.M):
        runner = "unittest"
    elif re.search(r"^Traceback \(most recent call last\)", log, re.M):
        runner = "plain"
    if runner:
        facts.append(_fact("runner", runner, source, ev(runner)))
    return facts


def declared_dependency_names(data: dict) -> Set[str]:
    """FIX_16 step 3: the packaging facts' dependency names as import-ish names (`python-dateutil>=2` → `python_dateutil`)."""
    out: Set[str] = set()
    for f in data.get("facts") or []:
        if f.get("source") == "packaging" and f.get("fact") in ("dependencies", "dependency"):
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(f.get("value", "")))
            if m:
                out.add(m.group(1).lower().replace("-", "_"))
    return out


# owner 2026-09-30 (Lane A): the intent is optional and may be added or changed at any time, so the Builder checks
# the file every cycle and re-ranks when it moved. The hash is over what the file SAYS — the statement text/source
# and every fact's (fact, value, source, evidence) — never its clocks (`generated_at`, `submitted_at`,
# `recorded_at`): the same statement saved twice is the same intent. No file → the fixed sentinel ABSENT_HASH.
ABSENT_HASH = "absent"


def content_hash(target: Path | str) -> str:
    """sha256 hex of the intent file's content (clocks dropped); ABSENT_HASH when there is no file. One small read."""
    p = path(target)
    try:
        raw = p.read_bytes()
    except FileNotFoundError:
        return ABSENT_HASH
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return hashlib.sha256(raw).hexdigest()   # unparseable: the bytes themselves, so a later fix still reads as a change
    st = data.get("statement") if isinstance(data, dict) else None
    st = {"text": st.get("text"), "source": st.get("source")} if isinstance(st, dict) else None
    facts = [[f.get("fact"), f.get("value"), f.get("source"), f.get("evidence")]
             for f in ((data.get("facts") if isinstance(data, dict) else None) or []) if isinstance(f, dict)]
    canon = json.dumps({"statement": st, "facts": facts}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


if __name__ == "__main__":  # a hand read: python3 intent_file.py <target>
    import sys
    print(json.dumps(read(sys.argv[1]), indent=1))
