"""
GRANULARIZE HARNESS - mypy Integration
Type checks individual files for quick validation.
"""

import subprocess
import sys  # FIX_23 (2026-09-15): mypy runs under THIS interpreter, never a bare `python` from PATH
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class MypyEngine:
    """
    Runs mypy on individual files for type checking.

    Usage:
        engine = MypyEngine()
        passed, msg = engine.check_file(Path("some_module.py"))
    """

    def __init__(
        self,
        ignore_missing_imports: bool = False,
        strict: bool = False,
        python_version: str = '3.13',
        extra_args: Optional[list[str]] = None,
    ):
        """
        Args:
            ignore_missing_imports: Don't fail on missing third-party stubs
            strict: Enable strict mode (more checks)
            python_version: Target Python version for syntax/feature checks
            extra_args: Additional mypy arguments
        """
        self.ignore_missing_imports = ignore_missing_imports
        self.strict = strict
        self.python_version = python_version
        self.extra_args = extra_args or []

        # Check mypy availability once at init
        self._mypy_available = self._check_mypy()

    def _check_mypy(self) -> bool:
        """Check if mypy is installed"""
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'mypy', '--version'],   # FIX_23: the engine interpreter
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"mypy available: {version} (via {sys.executable})")
                return True
            logger.warning(f"mypy: NOT MEASURED (mypy not importable by {sys.executable}: rc {result.returncode})")
            return False
        except Exception as e:
            logger.warning(f"mypy: NOT MEASURED (mypy not importable by {sys.executable}: {e})")
            return False

    def check_file(self, file_path: Path) -> tuple[Optional[bool], str]:
        """
        Type check a single file.
        Returns (passed, message); passed is None when nothing was measured (FIX_23, 2026-09-15:
        a missing mypy is NOT MEASURED, never a silent pass).
        """
        if not self._mypy_available:
            return (None, f'mypy: NOT MEASURED (mypy not importable by {sys.executable})')

        if not file_path.exists():
            return (False, f"file not found: {file_path}")

        # Build command
        cmd = [sys.executable, '-m', 'mypy']   # FIX_23: the engine interpreter, never PATH's `python`

        # Target python version
        cmd.extend(['--python-version', self.python_version])

        # Don't descend into site-packages
        cmd.extend(['--exclude', 'site-packages'])

        if self.ignore_missing_imports:
            cmd.append('--ignore-missing-imports')

        if self.strict:
            cmd.append('--strict')

        # Compact machine-friendly output
        cmd.extend(['--no-error-summary', '--no-pretty'])

        cmd.extend(self.extra_args)
        cmd.append(str(file_path))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=file_path.parent,
            )

            if result.returncode == 0:
                return (True, 'type check passed')

            # Parse error lines
            errors = []
            for line in result.stdout.strip().split('\n'):
                if line and 'error:' in line:
                    # Extract just the error message part
                    if ': error:' in line:
                        error_part = line.split(': error:')[1].strip()
                        errors.append(error_part)
                    else:
                        errors.append(line)

            if errors:
                # Summarize (first few errors)
                error_summary = '; '.join(errors[:3])
                if len(errors) > 3:
                    error_summary += f" (+{len(errors) - 3} more)"
                return (False, error_summary)

            return (False, 'type check failed (unknown error)')

        except subprocess.TimeoutExpired:
            return (False, 'mypy timeout (30s)')
        except Exception as e:
            return (False, f"mypy error: {e}")


# Module-level singleton for harness integration
_engine: Optional[MypyEngine] = None


def init_mypy_validator(ignore_missing_imports: bool = True, strict: bool = False):
    """Initialize the mypy validator"""
    global _engine
    _engine = MypyEngine(
        ignore_missing_imports=ignore_missing_imports,
        strict=strict,
    )


def mypy_validator(path: Path) -> tuple[Optional[bool], str]:
    """Validator function for harness integration"""
    global _engine
    if _engine is None:
        _engine = MypyEngine()
    return _engine.check_file(path)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    if len(sys.argv) < 2:
        print('Usage: python mypy_validator.py <file.py> [--strict]')
        sys.exit(1)

    file_path = Path(sys.argv[1])
    strict = '--strict' in sys.argv

    engine = MypyEngine(strict=strict)
    passed, msg = engine.check_file(file_path)

    if passed is None:
        print(f"— {msg}")
        sys.exit(2)
    if passed:
        print(f"✓ {msg}")
    else:
        print(f"✗ {msg}")
        sys.exit(1)
