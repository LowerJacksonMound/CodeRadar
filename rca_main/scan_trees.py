"""ScanTrees — the per-scan shared tree store (FIX_39, owner Q1 2026-09-15; closes I-04 + I-06).

THE HOTSPOT IT REPLACES.  `CallerTracer._find_direct_callers_async` read and `ast.parse`d EVERY live
file of the target for EVERY failure site, then again for every direct caller down to depth 3
(`rca_unit.py:94/181`).  `validate_directory_async` builds ONE RootCauseUnit per scan but calls
`analyze()` once per failed row, so the cost was `sites x files x depth` reads and parses where it
should be `files`.  Run 113 at size: pygments 397 files / 1377 defs — 73 sites on 17 files in 14 min
(mean 11.6 s/site, max 94 s on `lexer.py`), the NOAI gate timed out at 900 s and a few-hundred-file
repo never reached MONITORING (I-04).

WHAT THIS IS.  One store, built once per scan from the SAME whitelist-filtered live list the
validator already hands down (plan item 6, 2026-09-05 — this unit never walks on its own).  Each file
is read once and parsed once; in that one pass the two indices the caller search needs are derived,
so the search itself is a dict lookup.

I-06 (the same code, fixed together).  The old loop gathered with `return_exceptions=True` and logged
a failure at DEBUG, so a swallowed read/parse error dropped a caller candidate silently and the
published `FRN-001 ... RootCause: N candidate file(s)` fluttered by one between runs (38/39, 52/53).
Here a file that cannot be read or parsed is recorded ONCE, in `errors`, counted in `stats()` and
published by the validator — never a silently missing candidate.  The same tree gives the same
candidate list every run.

The store is deliberately dumb: it holds text and trees, it does not decide anything.  Every
judgement stays where it was.
"""

from __future__ import annotations

import ast
import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, cast

from no_aivalidator.noai_validator.utils import read_source   # A1 / C3 (g): the one target reader

logger = logging.getLogger(__name__)


class _Loaded:
    """One live file, read once and parsed once."""

    __slots__ = ("path", "text", "tree", "error")

    def __init__(self, path: str, text: Optional[str], tree: Optional[ast.AST], error: str) -> None:
        self.path = path
        self.text = text
        self.tree = tree
        self.error = error


class ScanTrees:
    """Every live file of one scan, read once and parsed once, with the caller indices."""

    def __init__(self, repo_root: str, files: Iterable[Any]) -> None:
        self.repo_root = os.path.abspath(str(repo_root))
        self.paths: List[str] = [os.path.abspath(str(f)) for f in (files or ())]
        self.loaded: Dict[str, _Loaded] = {}
        # The three import indices reproduce, one for one, the three tests the old per-site scanner
        # ran on every file (`_check_file_for_caller_async`): `import X` matched X by EQUALITY,
        # `from A.B import ...` matched by SUBSTRING on the module path, and the alias list of a
        # `from ... import leaf` matched by EQUALITY (FIX_32, run 100 launch A). Keeping them apart
        # is what keeps the answer identical — one index with everything in it matches more.
        self.import_exact: Dict[str, Set[str]] = {}    # ast.Import alias.name  -> files (equality)
        self.from_modules: Dict[str, Set[str]] = {}    # ast.ImportFrom .module -> files (substring)
        self.from_aliases: Dict[str, Set[str]] = {}    # ast.ImportFrom alias   -> files (equality)
        # called name -> the files that call it (bare name and attribute)
        self.callers_of: Dict[str, Set[str]] = {}
        # files that did not parse: their text, for the caller search's text fallback
        self.unparsed: Dict[str, str] = {}
        # path -> "<ExceptionType>: <message>", one row per file, published, never swallowed (I-06)
        self.errors: Dict[str, str] = {}
        self.reads = 0
        self.parses = 0
        self._loaded_once = False

    # ── build ───────────────────────────────────────────────────────────────

    async def load(self) -> "ScanTrees":
        """Read + parse every live file EXACTLY once. Idempotent per scan."""
        if self._loaded_once:
            return self
        results = await asyncio.gather(*(asyncio.to_thread(self._load_one, p) for p in self.paths))
        for item in results:
            self.loaded[item.path] = item
            if item.error:
                self.errors[item.path] = item.error
            if item.tree is not None:
                self._index(item)
            elif item.text is not None:
                self.unparsed[item.path] = item.text
        self._loaded_once = True
        logger.info("ScanTrees: %s", self.stats_line())
        return self

    def _load_one(self, path: str) -> _Loaded:
        # C3 (g) / A1 (Q-H3b-4/5): `read_source` honours a UTF-8 BOM and a PEP 263 coding cookie,
        # so a BOM or latin-1 file parses instead of landing in `errors` as a SyntaxError; a file it
        # cannot decode (SyntaxError on the cookie, UnicodeDecodeError, OSError) is recorded in
        # `errors` with the exception's own name and published — never `errors="replace"`d into a
        # tree that is not the file's.
        try:
            text = read_source(Path(path))
        except Exception as e:
            return _Loaded(path, None, None, f"{type(e).__name__}: {e}")
        self.reads += 1
        try:
            tree = ast.parse(text)
        except SyntaxError as e:
            self.parses += 1
            return _Loaded(path, text, None, f"SyntaxError: {e}")
        except Exception as e:
            self.parses += 1
            return _Loaded(path, text, None, f"{type(e).__name__}: {e}")
        self.parses += 1
        return _Loaded(path, text, tree, "")

    def _index(self, item: _Loaded) -> None:
        """The one walk per file that feeds both indices (the same node tests the old per-site
        `_check_file_for_caller_async` ran — moved from per (site, file) to per file)."""
        path = item.path
        calls = self.callers_of
        # `load()` only calls _index when `item.tree is not None`; the cast states that guard.
        for node in ast.walk(cast(ast.AST, item.tree)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.import_exact.setdefault(alias.name, set()).add(path)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.from_modules.setdefault(node.module, set()).add(path)
                # FIX_32 (run 100 launch A): `from . import leaf` / `from pkg import leaf` names the
                # module in the alias list, not in `module` — a caller all the same.
                for alias in node.names:
                    self.from_aliases.setdefault(alias.name, set()).add(path)
            elif isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name):
                    calls.setdefault(fn.id, set()).add(path)
                elif isinstance(fn, ast.Attribute):
                    calls.setdefault(fn.attr, set()).add(path)

    # ── the caller search, as a lookup ───────────────────────────────────────

    def direct_callers(self, target_file: str, target_function: str = "") -> List[str]:
        """The files that import `target_file`'s module, or call `target_function`.

        The same answer `_find_direct_callers_async` computed, from the indices built in the one
        pass. `target_file` itself is not its own caller.
        """
        target_name = os.path.basename(str(target_file))
        if target_name.endswith(".py"):
            target_name = target_name[:-3]
        target_abs = os.path.abspath(str(target_file))

        found: Set[str] = set(self.import_exact.get(target_name, ()))
        found |= set(self.from_aliases.get(target_name, ()))
        # `from A.B import ...` matched by SUBSTRING on the module path, as it always did
        for module, files in self.from_modules.items():
            if target_name and target_name in module:
                found |= files
        if target_function:
            # The old scanner gated EVERY test behind `if target_name not in content: return None`,
            # so a file that called the function without naming the module was never a caller. The
            # text is in the store, so the gate costs nothing here and the answer stays identical.
            for path in self.callers_of.get(target_function, ()):
                item = self.loaded.get(path)
                if item is not None and item.text is not None and target_name in item.text:
                    found.add(path)

        # the SyntaxError branch of the old scanner: its patterns, against the text held here
        if self.unparsed:
            patterns = [f"import {target_name}", f"from {target_name}",
                        f"from .{target_name}", f"from ..{target_name}"]
            if target_function:
                patterns.append(f"{target_function}(")
            for path, text in self.unparsed.items():
                if target_name and target_name not in text:
                    continue
                if any(p in text for p in patterns):
                    found.add(path)

        found.discard(target_abs)
        return sorted(found)

    # ── the text/tree a reader already paid for ─────────────────────────────

    def text_of(self, path: str) -> Optional[str]:
        item = self.loaded.get(os.path.abspath(str(path)))
        return None if item is None else item.text

    def tree_of(self, path: str) -> Optional[ast.AST]:
        item = self.loaded.get(os.path.abspath(str(path)))
        return None if item is None else item.tree

    def defines(self, term: str) -> Optional[str]:
        """The first live file whose text carries `class T` / `def t` / `T =` — off the store,
        so `_find_definition_async` stops re-reading the repo once per keyword per site."""
        patterns = (f"class {term}", f"def {term}", f"{term} =")
        for path in self.paths:
            item = self.loaded.get(path)
            if item is None or item.text is None:
                continue
            if any(p in item.text for p in patterns):
                return path
        return None

    # ── what is published ───────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        return {
            "files": len(self.paths),
            "reads": self.reads,
            "parses": self.parses,
            "parsed": sum(1 for i in self.loaded.values() if i.tree is not None),
            "unparsed": len(self.unparsed),
            "errors": len(self.errors),
            "modules_indexed": len(self.import_exact) + len(self.from_modules) + len(self.from_aliases),
            "call_names_indexed": len(self.callers_of),
        }

    def stats_line(self) -> str:
        s = self.stats()
        return (f"{s['files']} live file(s), {s['reads']} read(s), {s['parses']} parse(s) "
                f"— ONE per file per scan; {s['parsed']} parsed, {s['unparsed']} unparsed, "
                f"{s['errors']} load error(s) (published, not swallowed — I-06); "
                f"{s['modules_indexed']} module name(s), {s['call_names_indexed']} call name(s) indexed")
