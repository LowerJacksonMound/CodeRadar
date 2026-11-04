"""
Harness - Validation and testing utilities.

Provides:
- contracts: Contract validation and violation logging
- crc_engine: Code fingerprinting and baseline comparison
- mypy_validator: MyPy type checking integration
- watcher: File system watching for hot reload (requires watchdog)
"""

from .contracts import (
    ContractViolation,
    init_contract_logging,
)

from .crc_engine import (
    FunctionFingerprint,
    CRCBaseline,
    CRCEngine,
)

from .mypy_validator import (
    MypyEngine,
    init_mypy_validator,
    mypy_validator,
)

# Watcher requires watchdog (optional dependency)
try:
    from .watcher import (
        FileChange,
        HarnessState,
        PythonFileHandler,
    )
    WATCHER_AVAILABLE = True
except ImportError:
    WATCHER_AVAILABLE = False
    FileChange = None  # type: ignore[assignment,misc]
    HarnessState = None  # type: ignore[assignment,misc]
    PythonFileHandler = None  # type: ignore[assignment,misc]

__all__ = [
    # contracts
    "ContractViolation",
    "init_contract_logging",
    # crc_engine
    "FunctionFingerprint",
    "CRCBaseline",
    "CRCEngine",
    # mypy_validator
    "MypyEngine",
    "init_mypy_validator",
    "mypy_validator",
    # watcher (optional)
    "WATCHER_AVAILABLE",
    "FileChange",
    "HarnessState",
    "PythonFileHandler",
]
