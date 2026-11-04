"""
GRANULARIZE HARNESS - Runtime Contracts (Dyno)
Decorator for pre/post condition checking during actual execution.
"""

import asyncio
import functools
import inspect
import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Callable, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# Global log file path
_contract_log: Optional[Path] = None


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
class ContractViolation:
    """Record of a contract violation"""
    timestamp: str
    function: str
    file: str
    lineno: int
    violation_type: str  # 'precondition' or 'postcondition'
    condition: str
    args: str
    kwargs: str
    result: Optional[str] = None
    error: Optional[str] = None


def init_contract_logging(log_path: Path):
    """Initialize contract violation logging"""
    global _contract_log
    _contract_log = log_path
    _contract_log.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Contract logging to: {_contract_log}")


def _log_violation(violation: ContractViolation):
    """Log a contract violation to file"""
    global _contract_log
    
    # Always log to logger
    logger.error(
        f"CONTRACT VIOLATION in {violation.function}: "
        f"{violation.violation_type} failed - {violation.condition}"
    )
    
    # Log to file if configured
    if _contract_log:
        try:
            with open(_contract_log, 'a') as f:
                f.write(json.dumps(asdict(violation)) + '\n')
        except Exception as e:
            logger.error(f"Failed to log violation: {e}")


def contract(
    pre: Optional[Callable[..., bool]] = None,
    post: Optional[Callable[..., bool]] = None,
    pre_msg: str = "precondition failed",
    post_msg: str = "postcondition failed",
    strict: bool = True
):
    """
    Decorator for runtime contract checking.
    
    Args:
        pre: Precondition function that receives (*args, **kwargs) and returns bool
        post: Postcondition function that receives (result, *args, **kwargs) and returns bool
        pre_msg: Message if precondition fails
        post_msg: Message if postcondition fails
    
    Usage:
        @contract(
            pre=lambda x, y: x > 0 and y > 0,
            post=lambda result, x, y: result == x + y
        )
        def add(x: int, y: int) -> int:
            return x + y
    """
    def decorator(func: Callable) -> Callable:
        func_name = func.__qualname__

        def _check_pre(*args, **kwargs):
            """Check precondition. Raises if strict, logs-only otherwise."""
            if pre is not None:
                try:
                    if not pre(*args, **kwargs):
                        violation = ContractViolation(
                            timestamp=datetime.now().isoformat(),
                            function=func_name,
                            file=func.__code__.co_filename,
                            lineno=func.__code__.co_firstlineno,
                            violation_type="precondition",
                            condition=pre_msg,
                            args=str(args)[:200],
                            kwargs=str(kwargs)[:200]
                        )
                        _log_violation(violation)
                        if strict:
                            raise AssertionError(f"Precondition failed for {func_name}: {pre_msg}")
                except AssertionError:
                    if strict:
                        raise
                except Exception as e:
                    logger.warning(f"Precondition check error in {func_name}: {e}")

        def _check_post(result, *args, **kwargs):
            """Check postcondition. Raises if strict, logs-only otherwise."""
            if post is not None:
                try:
                    if not post(result, *args, **kwargs):
                        violation = ContractViolation(
                            timestamp=datetime.now().isoformat(),
                            function=func_name,
                            file=func.__code__.co_filename,
                            lineno=func.__code__.co_firstlineno,
                            violation_type="postcondition",
                            condition=post_msg,
                            args=str(args)[:200],
                            kwargs=str(kwargs)[:200],
                            result=str(result)[:200]
                        )
                        _log_violation(violation)
                        if strict:
                            raise AssertionError(f"Postcondition failed for {func_name}: {post_msg}")
                except AssertionError:
                    if strict:
                        raise
                except Exception as e:
                    logger.warning(f"Postcondition check error in {func_name}: {e}")

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            _check_pre(*args, **kwargs)
            result = await func(*args, **kwargs)
            _check_post(result, *args, **kwargs)
            return result

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            _check_pre(*args, **kwargs)
            result = func(*args, **kwargs)
            _check_post(result, *args, **kwargs)
            return result

        return async_wrapper if inspect.iscoroutinefunction(func) else sync_wrapper
    return decorator


def require(condition: bool, msg: str = "requirement not met"):
    """
    Inline precondition check.
    
    Usage:
        def process(items):
            require(len(items) > 0, "items cannot be empty")
            ...
    """
    if not condition:
        raise AssertionError(f"Requirement failed: {msg}")


def ensure(condition: bool, msg: str = "guarantee not met"):
    """
    Inline postcondition check.
    
    Usage:
        def process(items):
            result = do_work(items)
            ensure(result is not None, "result must not be None")
            return result
    """
    if not condition:
        raise AssertionError(f"Postcondition failed: {msg}")


def get_recent_violations(log_path: Path, n: int = 10) -> list[ContractViolation]:
    """Read recent violations from log file"""
    if not log_path.exists():
        return []
    
    violations = []
    try:
        with open(log_path, 'r') as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    violations.append(ContractViolation(**data))
    except Exception as e:
        logger.error(f"Failed to read violations: {e}")
    
    return violations[-n:]


# === VALIDATOR FUNCTION (for harness integration) ===

def contract_validator(path: Path) -> tuple[bool, str]:
    """
    Validator that checks for recent contract violations.
    Note: This doesn't validate the file itself - contracts fire during runtime.
    This just reports if there were recent violations.
    """
    global _contract_log
    
    if _contract_log is None or not _contract_log.exists():
        return True, "no contract violations logged"
    
    violations = get_recent_violations(_contract_log, n=5)
    if not violations:
        return True, "no contract violations logged"
    
    # Check for recent violations (last 60 seconds)
    recent = []
    cutoff = datetime.now().timestamp() - 60
    
    for v in violations:
        try:
            v_time = datetime.fromisoformat(v.timestamp).timestamp()
            if v_time > cutoff:
                recent.append(v)
        except:
            pass
    
    if recent:
        return False, f"{len(recent)} recent violation(s): {recent[0].function}"

    return True, "no recent contract violations"


# === CONTRACT PRESENCE SCANNER ===

def scan_contract_decorators(repo_path: Path) -> list[dict]:
    """
    AST scan to detect functions decorated with @contract.

    Returns a list of dicts:
        [{'function': 'clamp', 'file': 'utils.py', 'lineno': 94,
          'has_pre': True, 'has_post': True,
          'pre_msg': 'low must be <= high',
          'post_msg': 'result must be within [low, high]'}]
    """
    import ast

    results: list[dict] = []

    # FIX_13 / FIX_15 (2026-09-10): the ONE walk — the by-name skip ('__pycache__', '.venv', 'venv',
    # '.git') is gone (venv by size, never by name; `.git` / `__pycache__` are scan_scope hard-skips).
    for py_file in _scan_scope().iter_live_py(repo_path):
        try:
            source = py_file.read_text(encoding='utf-8')
            tree = ast.parse(source, filename=str(py_file))
        except Exception as _e:  # EXCISED cut 3 batch 2 (2026-09-06, agreed): swallow → reported
            logger.warning("reported, not swallowed (cut 3): %s: %r", 'scan_contract_decorators', _e)
            continue

        try:
            rel = str(py_file.relative_to(repo_path))
        except ValueError:
            rel = py_file.name

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if _is_contract_call(dec):
                    info: dict = {
                        'function': node.name,
                        'file': rel,
                        'lineno': node.lineno,
                        'has_pre': False,
                        'has_post': False,
                        'pre_msg': '',
                        'post_msg': '',
                    }
                    # Extract keyword args from @contract(...)
                    if isinstance(dec, ast.Call):
                        for kw in dec.keywords:
                            if kw.arg == 'pre':
                                info['has_pre'] = True
                            elif kw.arg == 'post':
                                info['has_post'] = True
                            elif kw.arg == 'pre_msg' and isinstance(kw.value, ast.Constant):
                                info['pre_msg'] = str(kw.value.value)
                            elif kw.arg == 'post_msg' and isinstance(kw.value, ast.Constant):
                                info['post_msg'] = str(kw.value.value)
                    results.append(info)

    return results


def _is_contract_call(node) -> bool:
    """Check if a decorator node is @contract or @contract(...)."""
    import ast
    # @contract (bare name — unusual but valid)
    if isinstance(node, ast.Name) and node.id == 'contract':
        return True
    # @contract(pre=..., post=...)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id == 'contract':
            return True
        # module.contract(...)
        if isinstance(func, ast.Attribute) and func.attr == 'contract':
            return True
    return False


# === CLI ===

if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    print("Contract decorator test")
    print("=" * 40)
    
    # Initialize logging
    test_log = Path(__file__).parent.parent / "daemon_log" / "contract_test.log"
    if test_log.exists():
        test_log.unlink()
    init_contract_logging(test_log)
    
    # Define test function with contracts
    @contract(
        pre=lambda x, y: x > 0 and y > 0,
        pre_msg="both arguments must be positive",
        post=lambda result, x, y: result == x + y,
        post_msg="result must equal x + y"
    )
    def add_positive(x: int, y: int) -> int:
        return x + y
    
    # Test 1: Valid call
    print("\n1. Valid call: add_positive(2, 3)")
    try:
        result = add_positive(2, 3)
        print(f"   ✓ Result: {result}")
    except AssertionError as e:
        print(f"   ✗ Error: {e}")
    
    # Test 2: Precondition violation
    print("\n2. Invalid call: add_positive(-1, 3)")
    try:
        result = add_positive(-1, 3)
        print(f"   ✓ Result: {result}")
    except AssertionError as e:
        print(f"   ✗ Error: {e}")
    
    # Test 3: Postcondition violation (fake buggy function)
    @contract(
        post=lambda result, x: result == x * 2,
        post_msg="result must be double the input"
    )
    def double(x: int) -> int:
        return x + 1  # BUG: should be x * 2
    
    print("\n3. Buggy function: double(5) with postcondition")
    try:
        result = double(5)
        print(f"   ✓ Result: {result}")
    except AssertionError as e:
        print(f"   ✗ Error: {e}")
    
    # Show logged violations
    print("\n" + "=" * 40)
    print("Logged violations:")
    violations = get_recent_violations(test_log)
    for v in violations:
        print(f"  - {v.function}: {v.violation_type} - {v.condition}")
    
    print("\n✓ Contract decorator working")
