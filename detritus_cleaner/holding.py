"""Holding management for safe file backup and restoration."""

from __future__ import annotations

import asyncio
import json
import shutil
import hashlib
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Set, Dict, Any, Optional

from detritus_cleaner.models import (
    HoldingManifest,
    FileMetadata,
    ManifestCorruptedError,
    HoldingError,
    ProgressCallback,
)
from detritus_cleaner.utils import compute_file_checksum, is_safe_path, logger, TRACING_ENABLED, emit_trace


__all__ = ['HoldingManager']


class HoldingManager:
    """
    Handles safe movement of files to/from holding.
    Uses a manifest file with checksums to ensure exact restoration.
    """

    MANIFEST_FILENAME = "restore_manifest.json"

    def __init__(
        self,
        repo_path: Path,
        holding_dir_name: str,
        verify_checksums: bool = True
    ):
        self.repo_path = repo_path.resolve()
        self.holding_dir = self.repo_path / holding_dir_name
        self.manifest_file = self.holding_dir / self.MANIFEST_FILENAME
        self.verify_checksums = verify_checksums
        logger.debug(f"HoldingManager initialized: dir={self.holding_dir}, "
                      f"verify_checksums={verify_checksums}")

    async def _load_manifest(self) -> HoldingManifest:
        """Load existing manifest or create new one."""
        exists = await asyncio.to_thread(self.manifest_file.exists)
        if not exists:
            logger.debug("_load_manifest: no existing manifest, creating new")
            return HoldingManifest(repo_path=str(self.repo_path))

        try:
            content = await asyncio.to_thread(self.manifest_file.read_text, 'utf-8')
            data = json.loads(content)
            manifest = HoldingManifest.from_dict(data)
            # Warn if manifest version differs from current
            if manifest.version != HoldingManifest().version:
                logger.warning(
                    f"Manifest version mismatch: file={manifest.version}, "
                    f"current={HoldingManifest().version}. Proceeding with caution."
                )
            logger.debug(f"_load_manifest: loaded manifest with {len(manifest.files)} files")
            return manifest
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            raise ManifestCorruptedError(f"Corrupt manifest: {e}") from e

    async def _save_manifest(self, manifest: HoldingManifest) -> None:
        """Save manifest to disk."""
        await asyncio.to_thread(self.holding_dir.mkdir, parents=True, exist_ok=True)
        content = json.dumps(manifest.to_dict(), indent=2, sort_keys=True)
        await asyncio.to_thread(self.manifest_file.write_text, content, 'utf-8')
        logger.debug(f"_save_manifest: saved manifest with {len(manifest.files)} entries")

    async def holding_files(
        self,
        files: Set[str],
        progress_callback: Optional[ProgressCallback] = None
    ) -> Tuple[List[str], List[Tuple[str, str]]]:
        """
        Move files to holding and update manifest.

        Args:
            files: Set of relative paths to holding
            progress_callback: Optional callback for progress updates

        Returns:
            Tuple of (successfully moved files, failed files with errors)
        """
        import time as _time
        _q_start = _time.perf_counter()

        logger.debug(f"holding_files: starting with {len(files)} files")
        if TRACING_ENABLED:
            emit_trace('holding_files_start', success=True, elapsed=0,
                       layer='Holding', module='holding.py')

        if not files:
            logger.info("No files to holding")
            return [], []

        try:
            manifest = await self._load_manifest()
        except ManifestCorruptedError:
            logger.warning("Creating new manifest due to corruption")
            manifest = HoldingManifest(repo_path=str(self.repo_path))

        moved: List[str] = []
        failed: List[Tuple[str, str]] = []
        total = len(files)

        for idx, rel_path in enumerate(sorted(files), 1):
            if progress_callback:
                progress_callback(idx, total, f"Moving to holding {rel_path}")

            src = self.repo_path / rel_path

            # Safety checks
            if not is_safe_path(self.repo_path, src):
                failed.append((rel_path, "Path escapes repository"))
                continue

            if not await asyncio.to_thread(src.exists):
                failed.append((rel_path, "File not found"))
                continue

            if await asyncio.to_thread(src.is_symlink):
                failed.append((rel_path, "Symbolic link - skipped for safety"))
                continue

            if not await asyncio.to_thread(src.is_file):
                failed.append((rel_path, "Not a regular file"))
                continue

            # Generate safe holding name using SHA256 (truncated)
            path_hash = hashlib.sha256(rel_path.encode()).hexdigest()[:8]
            safe_name = f"{path_hash}_{src.name}"
            dst = self.holding_dir / safe_name

            # Handle name collisions
            counter = 1
            while await asyncio.to_thread(dst.exists):
                safe_name = f"{path_hash}_{counter}_{src.name}"
                dst = self.holding_dir / safe_name
                counter += 1

            try:
                # Compute checksum before move
                checksum = await compute_file_checksum(src) if self.verify_checksums else None
                if self.verify_checksums and checksum is None:
                    failed.append((rel_path, "Failed to compute checksum"))
                    continue
                stat_result = await asyncio.to_thread(src.stat)
                size_bytes = stat_result.st_size

                # Create holding dir
                await asyncio.to_thread(self.holding_dir.mkdir, parents=True, exist_ok=True)

                # Move file
                await asyncio.to_thread(shutil.move, str(src), str(dst))

                # Update manifest
                manifest.files[safe_name] = FileMetadata(
                    original_path=rel_path,
                    holding_name=safe_name,
                    size_bytes=size_bytes,
                    checksum=checksum or "",
                    moved_at=datetime.now().isoformat(),
                    status_before_move="detritus"
                )

                moved.append(rel_path)
                logger.debug(f"Holdingd: {rel_path} -> {safe_name}")

            except OSError as e:
                failed.append((rel_path, f"Move failed: {e}"))
                logger.error(f"Failed to holding {rel_path}: {e}")

        # Save updated manifest
        try:
            await self._save_manifest(manifest)
        except OSError as e:
            raise HoldingError(f"Failed to save manifest: {e}") from e

        logger.info(f"Holdingd {len(moved)}/{total} files")
        if failed:
            logger.warning(f"Failed to holding {len(failed)} files")
            for path, reason in failed:
                logger.debug(f"Holding failed: {path} - {reason}")

        if TRACING_ENABLED:
            emit_trace('holding_files_complete', success=(len(failed) == 0),
                       elapsed=_time.perf_counter() - _q_start,
                       layer='Holding', module='holding.py')

        return moved, failed

    async def restore_files(
        self,
        progress_callback: Optional[ProgressCallback] = None
    ) -> Tuple[List[str], List[Tuple[str, str]]]:
        """
        Restore all files using the manifest.

        Returns:
            Tuple of (successfully restored files, failed files with errors)
        """
        import time as _time
        _r_start = _time.perf_counter()

        logger.debug("restore_files: starting restoration")
        if TRACING_ENABLED:
            emit_trace('restore_files_start', success=True, elapsed=0,
                       layer='Holding', module='holding.py')

        if not await asyncio.to_thread(self.manifest_file.exists):
            logger.warning("No manifest found - nothing to restore")
            return [], []

        try:
            manifest = await self._load_manifest()
        except ManifestCorruptedError as e:
            return [], [("manifest", str(e))]

        restored: List[str] = []
        failed: List[Tuple[str, str]] = []
        total = len(manifest.files)
        logger.debug(f"restore_files: manifest has {total} entries")

        for idx, (safe_name, metadata) in enumerate(manifest.files.items(), 1):
            if progress_callback:
                progress_callback(idx, total, f"Restoring {metadata.original_path}")

            src = self.holding_dir / safe_name
            dst = self.repo_path / metadata.original_path

            # Safety checks
            if not is_safe_path(self.repo_path, dst):
                failed.append((metadata.original_path, "Path escapes repository"))
                continue

            if not await asyncio.to_thread(src.exists):
                failed.append((metadata.original_path, "Backup file missing"))
                continue

            if await asyncio.to_thread(dst.exists):
                failed.append((metadata.original_path, "Target already exists"))
                continue

            try:
                # Verify checksum if available
                if self.verify_checksums and metadata.checksum:
                    current_checksum = await compute_file_checksum(src)
                    if current_checksum is None:
                        failed.append((
                            metadata.original_path,
                            "Failed to compute checksum for verification"
                        ))
                        continue
                    if current_checksum != metadata.checksum:
                        failed.append((
                            metadata.original_path,
                            f"Checksum mismatch: {current_checksum} != {metadata.checksum}"
                        ))
                        continue

                # Create parent directories
                await asyncio.to_thread(dst.parent.mkdir, parents=True, exist_ok=True)

                # Restore file
                await asyncio.to_thread(shutil.move, str(src), str(dst))
                restored.append(metadata.original_path)
                logger.debug(f"Restored: {safe_name} -> {metadata.original_path}")

            except OSError as e:
                failed.append((metadata.original_path, f"Restore failed: {e}"))
                logger.error(f"Failed to restore {metadata.original_path}: {e}")

        # Clean up holding directory if all files restored successfully
        if not failed and restored:
            try:
                await asyncio.to_thread(shutil.rmtree, self.holding_dir)
                logger.info(f"Removed holding directory ({len(restored)}/{total} files restored)")
            except OSError as e:
                logger.warning(f"Failed to remove holding directory: {e}")

        logger.info(f"Restored {len(restored)}/{total} files")
        if failed:
            logger.warning(f"Failed to restore {len(failed)} files")
            for path, reason in failed:
                logger.debug(f"Restore failed: {path} - {reason}")

        if TRACING_ENABLED:
            emit_trace('restore_files_complete', success=(len(failed) == 0),
                       elapsed=_time.perf_counter() - _r_start,
                       layer='Holding', module='holding.py')

        return restored, failed

    async def list_held(self) -> List[Dict[str, Any]]:
        """List all files currently in holding."""
        if not await asyncio.to_thread(self.manifest_file.exists):
            logger.debug("list_held: no manifest file found")
            return []

        try:
            manifest = await self._load_manifest()
            result = [asdict(metadata) for metadata in manifest.files.values()]
            logger.debug(f"list_held: returning {len(result)} entries")
            return result
        except ManifestCorruptedError:
            logger.debug("list_held: manifest corrupted, returning empty")
            return []
