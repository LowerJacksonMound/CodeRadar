"""Data models, enums, and exceptions for detritus cleaner."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Set, List, Dict, Tuple, Optional, Any, Protocol


__all__ = [
    # Protocols
    'ProgressCallback',
    # Exceptions
    'DetritusCleanerError',
    'ManifestCorruptedError', 
    'HoldingError',
    'ValidationError',
    # Enums
    'FileStatus',
    # Data classes
    'FileMetadata',
    'HoldingManifest',
    'DetritusConfig',
    'CleanseResult',
]


# =============================================================================
# Protocols
# =============================================================================

class ProgressCallback(Protocol):
    """Protocol for progress reporting."""
    def __call__(self, current: int, total: int, message: str) -> None:
        ...


# =============================================================================
# Exceptions
# =============================================================================

class DetritusCleanerError(Exception):
    """Base exception for detritus cleaner."""
    pass


class ManifestCorruptedError(DetritusCleanerError):
    """Raised when holding manifest is corrupted."""
    pass


class HoldingError(DetritusCleanerError):
    """Raised when holding operation fails."""
    pass


class ValidationError(DetritusCleanerError):
    """Raised when validation fails."""
    pass


# =============================================================================
# Enums
# =============================================================================

class FileStatus(Enum):
    """Status of a file in the analysis."""
    LIVE = "live"
    WHITELISTED = "whitelisted"
    DETRITUS = "detritus"
    EXCLUDED = "excluded"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class FileMetadata:
    """Metadata for a file in holding."""
    original_path: str
    holding_name: str
    size_bytes: int
    checksum: str  # SHA256
    moved_at: str  # ISO timestamp
    status_before_move: str


@dataclass
class HoldingManifest:
    """Complete manifest for holding restoration."""
    version: str = "2.0"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    repo_path: str = ""
    files: Dict[str, FileMetadata] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "repo_path": self.repo_path,
            "files": {k: asdict(v) for k, v in self.files.items()}
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HoldingManifest:
        manifest = cls(
            version=data.get("version", "2.0"),
            created_at=data.get("created_at", ""),
            repo_path=data.get("repo_path", "")
        )
        manifest.files = {
            k: FileMetadata(**v) for k, v in data.get("files", {}).items()
        }
        return manifest


@dataclass
class DetritusConfig:
    """Configuration for the cleaning process."""
    repo_path: Path
    dry_run: bool = False
    holding_dir_name: str = ".detritus_backup"
    additional_entry_points: Set[str] = field(default_factory=set)
    exclude_dirs: Set[str] = field(default_factory=lambda: {
        ".git", ".venv", ".tox", "__pycache__", "node_modules",
        ".pytest_cache", ".mypy_cache", "venv", "env"
    })
    exclude_patterns: Set[str] = field(default_factory=set)  # e.g., '*_generated.py', '*_pb2.py'
    max_concurrent_tasks: int = 50
    follow_symlinks: bool = False
    verify_checksums: bool = True
    log_level: int = 20  # logging.INFO


@dataclass
class CleanseResult:
    """Result of detritus cleanse operation."""
    live_files: Set[str] = field(default_factory=set)
    whitelisted_files: Set[str] = field(default_factory=set)
    detritus_files: Set[str] = field(default_factory=set)
    excluded_files: Set[str] = field(default_factory=set)
    moved_files: List[str] = field(default_factory=list)
    failed_files: List[Tuple[str, str]] = field(default_factory=list)
    manifest_path: Optional[str] = None
    total_scanned: int = 0
    circular_imports: List[Tuple[str, ...]] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    clean_duration_seconds: float = 0.0

    # Backward compatibility aliases
    @property
    def detritus(self) -> List[str]:
        """Backward compatibility: return detritus_files as sorted list."""
        return sorted(self.detritus_files)

    @property
    def preserved_files(self) -> Set[str]:
        """Backward compatibility: files that were preserved (live + whitelisted)."""
        return self.live_files | self.whitelisted_files

    def summary(self) -> Dict[str, Any]:
        """Generate a summary dict."""
        return {
            "total_scanned": self.total_scanned,
            "live_files": len(self.live_files),
            "whitelisted_files": len(self.whitelisted_files),
            "detritus_files": len(self.detritus_files),
            "excluded_files": len(self.excluded_files),
            "moved_files": len(self.moved_files),
            "failed_files": len(self.failed_files),
            "circular_imports": len(self.circular_imports),
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
            "clean_duration_seconds": round(self.clean_duration_seconds, 2)
        }
