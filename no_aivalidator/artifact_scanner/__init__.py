"""ARTIFACT SCANNER — one stage under that name (Item 3, 2026-09-10; ruled name RENAME_03).

    report = await analyze(target, files=None, *, whitelist=None)

Scope as ruled (owner 2026-09-09): (1) the stub / whitelist consult — every whole-file stub the scanner finds goes on
the whitelist as `stub:<kind>`; (5) the dot-dir intent sources — read for INTENT (`report.intent_facts`), classified
as artifacts; plus proxy classification BY CONTENT (`report.species[rel]`, the published `species` fact: "" | "test" |
"proxy:<kind>") — a proxy is drawn and judged as a proxy, never as the app: the Ranker withholds its verdict on every
row of a proxy file exactly as it does for test species, the evidence stays published. NOT this stage (ruled): the
species-by-dictionary scan (the detritus cleaner's), the config key=value reader (RCA's), the signature engine (the
validator's — it keeps receiving exactly what it receives today).

Whole-set facts the predicates need are measured ONCE here: `in_degree` (importers within the target, from the
detritus cleaner's ImportGraphBuilder) and `referenced_elsewhere` (a def / class name of the file used in another
file). The scanner READS the target only; it walks nothing of its own (`scan_scope.iter_live_py` / `iter_contained`).
"""
from __future__ import annotations

import ast
import asyncio
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from .species import PROXY_KINDS, SPECIES_VOCABULARY, SpeciesFact, classify, test_species
from .stubs import STUB_KINDS, file_stub_kind
from .intent_sources import IntentFact, collect as collect_intent

__all__ = ["analyze", "ArtifactReport", "SpeciesFact", "IntentFact", "STUB_KINDS", "PROXY_KINDS", "SPECIES_VOCABULARY", "test_species"]

STAGE_NAME = "ARTIFACTS"


@dataclass
class ArtifactReport:
    target: str
    species: Dict[str, SpeciesFact] = field(default_factory=dict)      # rel -> fact (every live .py)
    stubs: Dict[str, str] = field(default_factory=dict)                # rel -> stub kind (whole-file stubs)
    intent_facts: List[IntentFact] = field(default_factory=list)
    in_degree: Dict[str, int] = field(default_factory=dict)
    files: List[str] = field(default_factory=list)
    unparsed: List[str] = field(default_factory=list)

    def proxies(self) -> Dict[str, str]:
        return {rel: f.species for rel, f in self.species.items() if f.species.startswith("proxy:")}

    def whitelist_entries(self) -> List[dict]:
        """What the stage adds to the ONE whitelist (ruling 13 / 2026-09-09): whole-file stubs. Proxies and tests are
        NOT whitelisted — they are scanned and withheld."""
        return [{"path": rel, "reason": f"stub:{kind}"} for rel, kind in sorted(self.stubs.items())]

    def summary(self) -> dict:
        kinds = Counter(f.species for f in self.species.values() if f.species)
        return {
            "stage": STAGE_NAME,
            "files": len(self.files),
            "species": {k: v for k, v in sorted(kinds.items())},
            "proxies": sum(v for k, v in kinds.items() if k.startswith("proxy:")),
            "tests": kinds.get("test", 0),
            "stubs": dict(Counter(self.stubs.values())),
            "intent_sources": sorted({f.source for f in self.intent_facts}),
            "intent_facts": len(self.intent_facts),
            "unparsed": len(self.unparsed),
            "vocabulary": list(SPECIES_VOCABULARY),
        }

    def as_dict(self) -> dict:
        return {"target": self.target, "summary": self.summary(),
                "species": {rel: f.as_dict() for rel, f in sorted(self.species.items()) if f.species or f.also or f.path_prior},
                "stubs": dict(sorted(self.stubs.items())),
                "intent_facts": [f.as_dict() for f in self.intent_facts]}


def _live_py(target: Path) -> List[Path]:
    """The ONE walk (FIX_13 / 15): scan_scope.iter_live_py under the launcher's whitelist scope; the plain contained
    glob only when scan_scope is not importable (a hand call outside the tree)."""
    ss_dir = Path(__file__).resolve().parents[2] / "system_scripts"
    if str(ss_dir) not in sys.path:
        sys.path.insert(0, str(ss_dir))
    try:
        import scan_scope  # type: ignore
        return sorted(scan_scope.iter_live_py(target))
    except Exception:
        return sorted(p for p in target.rglob("*.py") if not p.is_symlink() and not any(part.startswith(".") for part in p.relative_to(target).parts))


def _iter_docs(target: Path) -> Iterable[Path]:
    ss_dir = Path(__file__).resolve().parents[2] / "system_scripts"
    if str(ss_dir) not in sys.path:
        sys.path.insert(0, str(ss_dir))
    docs = target / "docs"
    if not docs.is_dir():
        return []
    try:
        import scan_scope  # type: ignore
        return [p for p in scan_scope.iter_contained(docs, "*") if p.suffix in (".md", ".rst") and p.is_file()]
    except Exception:
        return [p for p in docs.rglob("*") if p.suffix in (".md", ".rst") and p.is_file() and not p.is_symlink()]


def _def_names(tree: ast.AST) -> Set[str]:
    return {n.name for n in getattr(tree, "body", []) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


def _used_names(tree: ast.AST) -> Set[str]:
    out: Set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
        elif isinstance(n, ast.ImportFrom):
            out.update(a.name for a in n.names)
    return out


async def _in_degrees(target: Path, rels: List[str]) -> Dict[str, int]:
    """Importers within the target per file — the detritus cleaner's graph builder, built once."""
    try:
        from detritus_cleaner.graph import ImportGraphBuilder
    except Exception:
        return {}
    b = ImportGraphBuilder(target)
    await b.build_graph_async(set(rels))
    return {rel: len(b.reverse_graph.get(rel, ())) for rel in rels}


async def analyze(target: Path | str, files: Optional[Iterable[Path]] = None, *,
                  whitelist: Optional[tuple] = None, whole_set: Optional[ArtifactReport] = None) -> ArtifactReport:
    """The stage. `files` = the live .py files to classify (default: the ONE walk); `whole_set` = a previous full
    report whose whole-set facts (in_degree, cross-file references) an incremental call reuses."""
    root = Path(target).resolve()
    paths = sorted(Path(p) for p in files) if files is not None else _live_py(root)
    rels = [p.relative_to(root).as_posix() if p.is_absolute() else Path(p).as_posix() for p in paths]
    report = ArtifactReport(target=str(root), files=list(rels))
    trees: Dict[str, ast.AST] = {}
    for p, rel in zip(paths, rels):
        ap = p if p.is_absolute() else root / p
        try:
            trees[rel] = ast.parse(ap.read_text(encoding="utf-8", errors="replace"), filename=str(ap))
        except (SyntaxError, ValueError, OSError):
            report.unparsed.append(rel)
    # whole-set facts, once
    if whole_set is not None and whole_set.in_degree:
        report.in_degree = dict(whole_set.in_degree)
        for rel in rels:
            report.in_degree.setdefault(rel, 0)
    else:
        report.in_degree = await _in_degrees(root, rels)
    defs_by_rel = {rel: _def_names(t) for rel, t in trees.items()}
    used_by_rel = {rel: _used_names(t) for rel, t in trees.items()}
    for rel, tree in trees.items():
        mine = defs_by_rel[rel]
        referenced = bool(mine) and any(mine & used for other, used in used_by_rel.items() if other != rel)
        fact = classify(tree, rel, in_degree=report.in_degree.get(rel), referenced_elsewhere=referenced if mine or True else None)
        report.species[rel] = fact
        kind = file_stub_kind(tree, rel)
        if kind:
            report.stubs[rel] = kind
    for p in sorted(root.glob("**/*.pyi")):
        if p.is_file() and not p.is_symlink():
            report.stubs[p.relative_to(root).as_posix()] = "pyi_stub_file"
    project_names: Set[str] = set()
    for rel, names in defs_by_rel.items():
        project_names |= names
        project_names.add(Path(rel).stem)
    report.intent_facts = await asyncio.to_thread(collect_intent, root, project_names, list(_iter_docs(root)))
    return report
