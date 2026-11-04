"""Dot-dir intent sources (Item 3, 2026-09-10): CI workflows, lint / type config, packaging, docs — read for INTENT,
classified as artifacts for scanning. Which sources carry which facts is `SPECIES_DICT.intent_sources` (the prose
mirror of this module); the facts are handed to the intent file (Item 8) as `IntentFact{fact, value, source,
evidence}` and published in the whitelist payload under `intent_facts` until Item 8's file exists.

Sources are looked up by EXPLICIT path signatures from the target root — the scanner adds no dot-skip (FIX_13) and
no walk of its own (`scan_scope.iter_contained` for the docs glob, FIX_15). Every value is a discrete fact; a
`domain_keywords` value is an INTERSECTION (README / docs identifier tokens ∩ the target's module / def names), never a
count threshold.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set

try:
    import tomllib  # 3.11+
except Exception:  # pragma: no cover
    tomllib = None  # type: ignore


@dataclass
class IntentFact:
    fact: str
    value: str
    source: str      # the intent-source species: ci_workflow | lint_config | type_config | packaging | docs | readme | changelog | contributing | pre_commit | tox
    evidence: str    # rel path

    def as_dict(self) -> dict:
        return {"fact": self.fact, "value": self.value, "source": self.source, "evidence": self.evidence}


_RUNNER_WORDS = ("pytest", "unittest", "tox", "nox", "make", "python -m", "poetry run", "pipenv run", "hatch run")
_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")
_PY_VER = re.compile(r"(?:python[-_ ]?version|python_requires|requires-python|target-version)\s*[:=]\s*[\"']?\s*[>=~^]*\s*([0-9]+\.[0-9]+)", re.I)


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _rel(p: Path, root: Path) -> str:
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.name


def _runners(text: str) -> Set[str]:
    return {w for w in _RUNNER_WORDS if w in text}


def _fenced_blocks(text: str) -> List[str]:
    return re.findall(r"```[a-zA-Z]*\n(.*?)```", text, re.S) + re.findall(r"^\s*(?:\$|>>>)\s+(.+)$", text, re.M)


def _ci_workflow(root: Path, out: List[IntentFact]) -> None:
    files: List[Path] = []
    wf = root / ".github" / "workflows"
    if wf.is_dir():
        files += [p for p in sorted(wf.iterdir()) if p.suffix in (".yml", ".yaml") and p.is_file()]
    for name in (".gitlab-ci.yml", "azure-pipelines.yml", ".travis.yml"):
        if (root / name).is_file():
            files.append(root / name)
    if (root / ".circleci" / "config.yml").is_file():
        files.append(root / ".circleci" / "config.yml")
    for p in files:
        text = _read(p)
        rel = _rel(p, root)
        for line in re.findall(r"^\s*-?\s*run:\s*(.+)$", text, re.M):
            for r in _runners(line):
                out.append(IntentFact("runner", r, "ci_workflow", rel))
            out.append(IntentFact("entry_points", line.strip()[:120], "ci_workflow", rel))
        for v in re.findall(r"python-version:\s*[\[\"']?\s*([0-9]+\.[0-9]+)", text):
            out.append(IntentFact("python_version", v, "ci_workflow", rel))


def _config_sections(root: Path, out: List[IntentFact]) -> None:
    for name, source, fact, tool in (("ruff.toml", "lint_config", "lint_tool", "ruff"), (".ruff.toml", "lint_config", "lint_tool", "ruff"),
                                     (".flake8", "lint_config", "lint_tool", "flake8"), (".pylintrc", "lint_config", "lint_tool", "pylint"),
                                     ("mypy.ini", "type_config", "typing_style", "mypy"), ("pyrightconfig.json", "type_config", "typing_style", "pyright"),
                                     ("tox.ini", "tox", "runner", "tox"), (".pre-commit-config.yaml", "pre_commit", "lint_tool", "pre-commit")):
        p = root / name
        if p.is_file():
            out.append(IntentFact(fact, tool, source, name))
            for v in _PY_VER.findall(_read(p)):
                out.append(IntentFact("python_version", v, source, name))
    cfg = root / "setup.cfg"
    if cfg.is_file():
        text = _read(cfg)
        if re.search(r"^\[flake8\]", text, re.M):
            out.append(IntentFact("lint_tool", "flake8", "lint_config", "setup.cfg#[flake8]"))
        if re.search(r"^\[mypy\]", text, re.M):
            out.append(IntentFact("typing_style", "mypy", "type_config", "setup.cfg#[mypy]"))
    pp = root / "pyproject.toml"
    if pp.is_file():
        text = _read(pp)
        for tool in ("ruff", "pylint"):
            if f"[tool.{tool}" in text:
                out.append(IntentFact("lint_tool", tool, "lint_config", f"pyproject.toml#[tool.{tool}]"))
        for tool in ("mypy", "pyright"):
            if f"[tool.{tool}" in text:
                out.append(IntentFact("typing_style", tool, "type_config", f"pyproject.toml#[tool.{tool}]"))


def _packaging(root: Path, out: List[IntentFact]) -> None:
    pp = root / "pyproject.toml"
    if pp.is_file():
        text = _read(pp)
        data = {}
        if tomllib is not None:
            try:
                data = tomllib.loads(text)
            except Exception:
                data = {}
        proj = data.get("project", {}) if isinstance(data, dict) else {}
        if proj.get("name"):
            out.append(IntentFact("package_name", str(proj["name"]), "packaging", "pyproject.toml"))
        if proj.get("requires-python"):
            out.append(IntentFact("python_version", str(proj["requires-python"]), "packaging", "pyproject.toml"))
        for d in proj.get("dependencies", []) or []:
            out.append(IntentFact("dependencies", str(d), "packaging", "pyproject.toml"))
        for grp, eps in (proj.get("scripts", {}) or {}).items():
            out.append(IntentFact("entry_points", f"{grp} = {eps}", "packaging", "pyproject.toml"))
        for fw in ("django", "flask", "fastapi", "click", "typer", "numpy", "pandas", "torch"):
            if any(str(d).lower().startswith(fw) for d in proj.get("dependencies", []) or []):
                out.append(IntentFact("frameworks", fw, "packaging", "pyproject.toml"))
    for name in ("setup.py", "setup.cfg", "Pipfile", "environment.yml"):
        p = root / name
        if p.is_file():
            text = _read(p)
            for v in _PY_VER.findall(text):
                out.append(IntentFact("python_version", v, "packaging", name))
            m = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.S)
            if m:
                for d in re.findall(r"[\"']([^\"']+)[\"']", m.group(1)):
                    out.append(IntentFact("dependencies", d, "packaging", name))
            m = re.search(r"\bname\s*=\s*[\"']([^\"']+)[\"']", text)
            if m and name != "environment.yml":
                out.append(IntentFact("package_name", m.group(1), "packaging", name))
    for p in sorted(root.glob("requirements*.txt")):
        if p.is_file():
            for line in _read(p).splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "-")):
                    out.append(IntentFact("dependencies", line, "packaging", p.name))


def _readme_docs(root: Path, out: List[IntentFact], project_names: Set[str], iter_docs: Optional[Iterable[Path]]) -> None:
    readmes = [p for p in sorted(root.glob("README*")) if p.is_file()]
    for p in readmes:
        text = _read(p)
        rel = p.name
        for r in _runners(text):
            out.append(IntentFact("runner", r, "readme", rel))
        for blk in _fenced_blocks(text):
            for r in _runners(blk):
                out.append(IntentFact("runner", r, "readme", rel))
            first = blk.strip().splitlines()[:1]
            if first and first[0].strip().startswith(("python ", "python3 ", "pip ", "pytest", "tox")):
                out.append(IntentFact("entry_points", first[0].strip()[:120], "readme", rel))
        head = "\n".join(text.splitlines()[:40])
        for kw in sorted(set(_IDENT.findall(head)) & project_names):
            out.append(IntentFact("domain_keywords", kw, "readme", rel))
    for name, source in (("CHANGELOG", "changelog"), ("CONTRIBUTING", "contributing")):
        for p in sorted(root.glob(name + "*")):
            if p.is_file():
                text = _read(p)
                for r in _runners(text):
                    out.append(IntentFact("runner", r, source, p.name))
                if source == "contributing":
                    for tool in ("ruff", "flake8", "pylint", "black"):
                        if tool in text:
                            out.append(IntentFact("lint_tool", tool, source, p.name))
    for p in iter_docs or []:
        text = _read(p)
        rel = _rel(p, root)
        head = "\n".join(text.splitlines()[:40])
        for kw in sorted(set(_IDENT.findall(head)) & project_names):
            out.append(IntentFact("domain_keywords", kw, "docs", rel))
        for blk in _fenced_blocks(text):
            first = blk.strip().splitlines()[:1]
            if first and first[0].strip().startswith(("python ", "python3 ")):
                out.append(IntentFact("entry_points", first[0].strip()[:120], "docs", rel))
    if (root / "mkdocs.yml").is_file():
        out.append(IntentFact("docs_tool", "mkdocs", "docs", "mkdocs.yml"))


def collect(root: Path, project_names: Set[str], iter_docs: Optional[Iterable[Path]] = None) -> List[IntentFact]:
    """Every intent fact the target's dot-dir / packaging / docs sources carry, deduplicated, source-tagged."""
    out: List[IntentFact] = []
    _ci_workflow(root, out)
    _config_sections(root, out)
    _packaging(root, out)
    _readme_docs(root, out, project_names, iter_docs)
    seen: Set[tuple] = set()
    uniq: List[IntentFact] = []
    for f in out:
        key = (f.fact, f.value, f.source, f.evidence)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq
