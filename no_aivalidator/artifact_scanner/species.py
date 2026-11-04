"""Species by CONTENT — the artifact scanner's classifier (Item 3, 2026-09-10).

`test_species` is the classifier that lived in `noai_validator/file_validation.py::_file_species` (calibrator A4 /
IG-5, 2026-09-06) — moved here unchanged; file_validation keeps a one-line alias. `classify` adds the proxy kinds
(`proxies.py`): a `.py` file that is a demo, a runner / harness, a path-hack script, a git script, an entry shim,
an assertion-only file, a setup script or a package marker is drawn and judged as a PROXY for not running the source,
never as the app (SPECIES_DICT `proxies._doctrine`: species signal = CONTENT, never name).

The published fact is `species` with the vocabulary "" | "test" | "proxy:<kind>", kind ∈ PROXY_KINDS — the same
fact the disposition table reads (owner ruling 2026-09-10: dispositions are per (rule, context)). Precedence for a
`.py`: test > pathhack > git > runner > entry_shim > demo > assertion_only > setup > package_marker; every kind that
matched is kept in `also` so nothing measured is dropped.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from . import proxies

_TEST_DIR_NAMES = frozenset({'test', 'tests', 'testing'})

PROXY_KINDS: Tuple[str, ...] = ("pathhack", "git", "runner", "entry_shim", "demo", "assertion_only", "setup", "package_marker")
SPECIES_VOCABULARY: Tuple[str, ...] = ("", "test") + tuple(f"proxy:{k}" for k in PROXY_KINDS)


@dataclass
class SpeciesFact:
    rel: str
    species: str = ""            # "" | "test" | "proxy:<kind>"
    by: str = "content"          # content | path (a path is only ever a PRIOR, never the species)
    reason: str = ""
    path_prior: bool = False
    also: List[str] = field(default_factory=list)   # every proxy kind that matched, in precedence order
    in_degree: Optional[int] = None                 # importers within the target (None = not measured)

    def as_dict(self) -> dict:
        return {"rel": self.rel, "species": self.species, "by": self.by, "reason": self.reason,
                "path_prior": self.path_prior, "also": list(self.also), "in_degree": self.in_degree}


def _base_name(b: ast.AST) -> str:
    if isinstance(b, ast.Name):
        return b.id
    if isinstance(b, ast.Attribute):
        return b.attr
    return ""


def test_species(tree: ast.AST, rel: str) -> Tuple[str, str, bool]:
    """(species, content_reason, path_prior). species is 'test' or '' — the only species THIS function names.
    Content: an unittest (not merely unittest.mock) or pytest import, a *TestCase class, or an ASSERTING top-level
    test_* function (IG-5: a test_* NAME alone is a convention). A tests/ dir or a test_*.py name is a PRIOR."""
    reasons: List[str] = []
    for n in ast.walk(tree):
        hit = None
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name == 'unittest' or a.name == 'pytest' or a.name.startswith('pytest.'):
                    hit = f'imports {a.name}'
        elif isinstance(n, ast.ImportFrom):
            mod = n.module or ''
            if mod == 'pytest' or mod.startswith('pytest.'):
                hit = f'from {mod} import'
            elif mod == 'unittest' and any(a.name != 'mock' for a in n.names):
                hit = 'from unittest import ' + ', '.join(a.name for a in n.names if a.name != 'mock')
            elif mod.startswith('unittest.') and mod != 'unittest.mock':
                hit = f'from {mod} import'
        if hit:
            reasons.append(hit)
            break
    for n in ast.walk(tree):
        if isinstance(n, ast.ClassDef) and any(_base_name(b).endswith('TestCase') for b in n.bases):
            reasons.append(f'class {n.name}(…TestCase)')
            break
    tops = [n for n in getattr(tree, 'body', []) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith('test_')]
    asserting = [n.name for n in tops if any(isinstance(x, ast.Assert) for x in ast.walk(n))]
    if asserting:
        reasons.append(f'{len(tops)} top-level test_* function(s), {len(asserting)} asserting')
    pp = Path(rel)
    prior = bool({x.lower() for x in pp.parts[:-1]} & _TEST_DIR_NAMES) or pp.name.startswith('test_') or pp.name.endswith('_test.py') or pp.name == 'conftest.py'
    return ('test' if reasons else ''), '; '.join(reasons), prior


def classify(tree: ast.AST, rel: str, *, in_degree: Optional[int] = None,
             referenced_elsewhere: Optional[bool] = None) -> SpeciesFact:
    """The species fact for one parsed `.py` file. `in_degree` = importers within the target (a whole-set fact the
    caller measures once); `referenced_elsewhere` = any def / class of this file is named by another file (the demo
    predicate). Either None = not measured → the predicates that need it do not fire (never a guess)."""
    sp, reason, prior = test_species(tree, rel)
    fact = SpeciesFact(rel=rel, species=sp, reason=reason, path_prior=prior, in_degree=in_degree)
    hits = proxies.matches(tree, rel, in_degree=in_degree, referenced_elsewhere=referenced_elsewhere)
    fact.also = [k for k, _ in hits]
    if sp:
        return fact                       # test species wins; the proxy hits ride in `also`
    if hits:
        kind, why = hits[0]
        fact.species = f"proxy:{kind}"
        fact.reason = why
    return fact
