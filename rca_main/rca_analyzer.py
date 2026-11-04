"""
RCA analyzer — cross-file config scanner for RCA (NOAIVALIDATOR).

Scans non-Python config artifacts (.ini, .cfg, .txt, .env) and extracts
key=value pairs so the detection pipeline can correlate magic numbers
in code with config file values.
"""

import configparser
import logging
import re
from pathlib import Path
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


# Type alias: maps (filepath, key) -> string value
ArtifactMap = Dict[Tuple[str, str], str]


class RCAAnalyzer:
    """Scans config files in a repo and returns a flat key-value map."""

    # Extensions to scan
    CONFIG_EXTENSIONS = {'.ini', '.cfg', '.txt', '.env', '.conf'}

    # Directories to skip
    SKIP_DIRS = {'.git', '__pycache__', '.tox', '.mypy_cache', 'node_modules',
                 '.venv', 'venv', '.eggs', '*.egg-info'}

    @classmethod
    def scan_config_files(cls, repo_path: Path) -> ArtifactMap:
        """
        Walk *repo_path* and extract key=value pairs from config files.

        Returns a dict mapping ``(relative_filepath, key)`` → ``value``
        (all strings). Numeric values are kept as their string
        representation so the caller can compare with ``str(magic_number)``.
        """
        result: ArtifactMap = {}

        if not repo_path.is_dir():
            return result

        # FIX_15 (2026-09-10): a contained walk — never through a symlink, never outside the root.
        # SKIP_DIRS (a name-based skip) stays until Item 3 moves this config reader into the
        # artifact scanner, where the whitelist is the one discovery — noted, not this fix's.
        from rca_main.constants import _scan_scope
        for path in _scan_scope().iter_contained(repo_path, '*'):
            if not path.is_file():
                continue
            # Skip hidden / cache dirs
            if any(part in cls.SKIP_DIRS for part in path.parts):
                continue
            if path.suffix not in cls.CONFIG_EXTENSIONS:
                continue

            rel = str(path.relative_to(repo_path))
            try:
                if path.suffix in ('.ini', '.cfg', '.conf'):
                    cls._parse_ini(path, rel, result)
                else:
                    cls._parse_keyvalue(path, rel, result)
            except Exception as exc:
                logger.debug("RCAAnalyzer: skipping %s (%s)", rel, exc)

        logger.info("RCAAnalyzer: scanned %d config entries from %s",
                     len(result), repo_path)
        return result

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ini(path: Path, rel: str, out: ArtifactMap) -> None:
        """Parse .ini / .cfg using configparser."""
        cp = configparser.ConfigParser()
        cp.read(str(path), encoding='utf-8')
        for section in cp.sections():
            for key, value in cp.items(section):
                out[(rel, key)] = value

    _KV_RE = re.compile(
        r'^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*[=:]\s*(.+?)\s*$'
    )

    @classmethod
    def _parse_keyvalue(cls, path: Path, rel: str, out: ArtifactMap) -> None:
        """Parse simple key=value / key: value files (.txt, .env)."""
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                m = cls._KV_RE.match(line)
                if m:
                    out[(rel, m.group(1))] = m.group(2)
