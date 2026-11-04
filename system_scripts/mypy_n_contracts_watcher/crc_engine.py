"""
GRANULARIZE HARNESS - CRC Engine
Detects changes to frozen functions by comparing AST hashes.
"""

import ast
import json
import hashlib
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


def _scope_excluded(path) -> bool:
    """F-CIRC-WALK (2026-09-05): consult the launch whitelist published via
    system_scripts/scan_scope; no scope published => nothing excluded."""
    try:
        import scan_scope
        return bool(scan_scope.excluded(path))
    except Exception:
        return False


def _scan_scope():
    """FIX_15 (2026-09-10): the ONE scan surface (system_scripts/scan_scope.py) — the walk itself is
    iter_live_py: whitelist, engine hard-skips, containment (no symlink, nothing outside the root)."""
    try:
        import scan_scope
    except ImportError:
        import sys as _sys
        from pathlib import Path as _P
        _sys.path.insert(0, str(_P(__file__).resolve().parents[1]))
        import scan_scope
    return scan_scope


@dataclass
class FunctionFingerprint:
    """Fingerprint of a single function"""
    name: str
    file: str
    lineno: int
    crc: str
    signature: str


@dataclass
class CRCBaseline:
    """Baseline snapshot of all function CRCs"""
    created: str
    functions: dict[str, dict[str, FunctionFingerprint]] = field(
        default_factory=dict
    )
    frozen: set[str] = field(default_factory=set)


class CRCEngine:
    """
    Computes and compares function-level CRCs.

    Usage:
        engine = CRCEngine()
        engine.load_baseline("baseline.json")
        passed, msg = engine.check_file(Path("some_module.py"))
    """

    def __init__(self):
        self.baseline = None

    def _extract_functions(self, file_path: Path) -> dict[str, FunctionFingerprint]:
        """Extract all function fingerprints from a Python file"""
        try:
            source = file_path.read_text()
            tree = ast.parse(source)
        except SyntaxError as e:
            logger.error(f"Syntax error in {file_path}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return {}

        functions = {}

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Hash the function's AST representation
                try:
                    body_str = ast.unparse(node)
                except Exception:
                    # Fallback for older Python
                    body_str = ast.dump(node)

                crc = hashlib.md5(body_str.encode()).hexdigest()[:8]

                # Build signature string
                args = ast.unparse(node.args) if hasattr(ast, 'unparse') else str(node.args)
                returns = ast.unparse(node.returns) if node.returns else 'None'
                signature = f"({args}) -> {returns}"

                fp = FunctionFingerprint(
                    name=node.name,
                    file=str(file_path),
                    lineno=node.lineno,
                    crc=crc,
                    signature=signature,
                )

                functions[node.name] = fp

        return functions

    def create_baseline(self, directories: list[Path], output_path: Path):
        """
        Scan directories and create a baseline snapshot.

        Preserves frozen entries from the previous baseline when the
        frozen function still exists in the new scan.
        """
        from datetime import datetime

        # Preserve frozen entries from existing baseline (if any)
        old_frozen = set()
        if self.baseline and self.baseline.frozen:
            old_frozen = self.baseline.frozen.copy()

        baseline = CRCBaseline(created=datetime.now().isoformat())

        for directory in directories:
            if not directory.exists():
                logger.warning(f"Directory not found: {directory}")
                continue

            # EXCISED cut 3 batch 5 (2026-09-06, line read): by-name skip ('__pycache__', '.venv', 'venv', '.git') removed —
            # venv by size, never by name; FIX_15 (2026-09-10): the walk IS the one discovery (iter_live_py, contained)
            for py_file in _scan_scope().iter_live_py(directory):
                rel_path = str(py_file)
                functions = self._extract_functions(py_file)

                if functions:
                    baseline.functions[rel_path] = functions

        # Restore frozen entries whose functions still exist
        if old_frozen:
            restored = 0
            for entry in old_frozen:
                filepath, funcname = entry.split('::', 1)
                if filepath in baseline.functions and funcname in baseline.functions[filepath]:
                    baseline.frozen.add(entry)
                    restored += 1
            if restored:
                logger.info(f"Baseline recreation: preserved {restored}/{len(old_frozen)} frozen entries")
            dropped = len(old_frozen) - restored
            if dropped:
                logger.info(f"Baseline recreation: dropped {dropped} frozen entries (functions no longer exist)")

        self.baseline = baseline
        self._save_baseline(baseline, output_path)

        total_funcs = sum(len(funcs) for funcs in baseline.functions.values())
        logger.info(f"Baseline created: {len(baseline.functions)} files, {total_funcs} functions")

        return baseline

    def _save_baseline(self, baseline: CRCBaseline, output_path: Path):
        """Save baseline to JSON"""
        data = {
            'created': baseline.created,
            'frozen': list(baseline.frozen),
            'functions': {},
        }

        for filepath, funcs in baseline.functions.items():
            data['functions'][filepath] = {  # type: ignore[index]  # FIX_54 ast-pos
                name: {
                    'name': fp.name,
                    'file': fp.file,
                    'lineno': fp.lineno,
                    'crc': fp.crc,
                    'signature': fp.signature,
                }
                for name, fp in funcs.items()
            }

        output_path.write_text(json.dumps(data, indent=2))
        logger.info(f"Baseline saved to: {output_path}")

    def load_baseline(self, baseline_path: Path) -> bool:
        """Load baseline from JSON"""
        if not baseline_path.exists():
            logger.error(f"Baseline not found: {baseline_path}")
            return False

        try:
            data = json.loads(baseline_path.read_text())

            self.baseline = CRCBaseline(
                created=data.get('created', 'unknown'),
                frozen=set(data.get('frozen', [])),
            )

            for filepath, funcs in data.get('functions', {}).items():
                self.baseline.functions[filepath] = {
                    name: FunctionFingerprint(**fp_data)
                    for name, fp_data in funcs.items()
                }

            total_funcs = sum(len(funcs) for funcs in self.baseline.functions.values())
            logger.info(f"Baseline loaded: {len(self.baseline.functions)} files, {total_funcs} functions")
            return True

        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return False

    def freeze_function(self, filepath: str, funcname: str):
        """Mark a function as frozen (should not change)"""
        if self.baseline:
            key = f"{filepath}::{funcname}"
            self.baseline.frozen.add(key)
            logger.info(f"Frozen: {key}")

    def check_file(self, file_path: Path) -> tuple[bool, str]:
        """
        Check a file against baseline.
        Returns (passed, message)
        """
        if not self.baseline:
            return (False, 'No baseline loaded')

        str_path = str(file_path)

        # Find matching baseline entry (by name suffix or full path)
        baseline_key = None
        for key in self.baseline.functions.keys():
            if key.endswith(file_path.name) or str_path.endswith(key) or key == str_path:
                baseline_key = key
                break

        if not baseline_key:
            # New file - not in baseline
            return (True, 'new file (not in baseline)')

        baseline_funcs = self.baseline.functions[baseline_key]
        current_funcs = self._extract_functions(file_path)

        violations = []

        for func_name, baseline_fp in baseline_funcs.items():
            frozen_key = f"{baseline_key}::{func_name}"

            if frozen_key in self.baseline.frozen:
                # Frozen function - must not change
                if func_name not in current_funcs:
                    violations.append(f"FROZEN function DELETED: {func_name}")
                elif current_funcs[func_name].crc != baseline_fp.crc:
                    violations.append(
                        f"FROZEN function CHANGED: {func_name} (was "
                        f"{baseline_fp.crc}, now {current_funcs[func_name].crc})"
                    )
            # Non-frozen functions can change freely
            elif func_name in current_funcs:
                if current_funcs[func_name].crc != baseline_fp.crc:
                    logger.debug(f"Function changed (not frozen): {func_name}")

        if violations:
            return (False, '; '.join(violations))

        return (True, 'CRC check passed')


# Module-level singleton for harness integration
_engine: Optional[CRCEngine] = None


def init_crc_validator(baseline_path: Path) -> bool:
    """Initialize the CRC validator with a baseline"""
    global _engine
    _engine = CRCEngine()
    return _engine.load_baseline(baseline_path)


def crc_validator(path: Path) -> tuple[bool, str]:
    """Validator function for harness integration"""
    if _engine is None:
        return (False, 'CRC engine not initialized')
    return _engine.check_file(path)


if __name__ == '__main__':
    import sys

    logging.basicConfig(level=logging.INFO, format='%(message)s')

    if len(sys.argv) < 2:
        print('Usage:')
        print('  Create baseline:  python crc_engine.py --create ./dir1 ./dir2 -o baseline.json')
        print('  Check file:       python crc_engine.py --check baseline.json ./file.py')
        print('  Freeze function:  python crc_engine.py --freeze baseline.json filepath funcname')
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == '--create':
        dirs = []
        output = Path('baseline.json')

        i = 2
        while i < len(sys.argv):
            if sys.argv[i] == '-o':
                output = Path(sys.argv[i + 1])
                i += 2
            else:
                dirs.append(Path(sys.argv[i]))
                i += 1

        engine = CRCEngine()
        engine.create_baseline(dirs, output)
        print(f"\n✓ Baseline created: {output}")

    elif cmd == '--check':
        baseline_path = Path(sys.argv[2])
        file_path = Path(sys.argv[3])

        engine = CRCEngine()
        if engine.load_baseline(baseline_path):
            passed, msg = engine.check_file(file_path)
            if passed:
                print(f"✓ {msg}")
            else:
                print(f"✗ {msg}")
                sys.exit(1)

    elif cmd == '--freeze':
        baseline_path = Path(sys.argv[2])
        filepath = sys.argv[3]
        funcname = sys.argv[4]

        engine = CRCEngine()
        if engine.load_baseline(baseline_path):
            engine.freeze_function(filepath, funcname)
            if engine.baseline:
                engine._save_baseline(engine.baseline, baseline_path)
            print(f"✓ Frozen: {filepath}::{funcname}")
