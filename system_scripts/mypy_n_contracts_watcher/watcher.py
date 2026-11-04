"""
GRANULARIZE HARNESS - File Watcher Core
Detects .py file changes and dispatches to validation engines.
"""

import time
import logging
from pathlib import Path
from typing import Callable
from dataclasses import dataclass, field
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger(__name__)


@dataclass
class FileChange:
    """Record of a file change event"""
    path: Path
    timestamp: datetime
    event_type: str  # 'modified' or 'created'


@dataclass
class HarnessState:
    """Central state for the harness"""
    watch_dirs: list[Path] = field(default_factory=list)
    recent_changes: list[FileChange] = field(default_factory=list)
    validators: list[Callable[[Path], tuple[bool, str]]] = field(default_factory=list)
    running: bool = False

    # Stats
    files_checked: int = 0
    validations_passed: int = 0
    validations_failed: int = 0


class PythonFileHandler(FileSystemEventHandler):
    """Handles filesystem events for .py files only"""

    def __init__(self, state: HarnessState, on_change: Callable[[Path], None]):
        self.state = state
        self.on_change = on_change
        self._debounce: dict = {}
        self._debounce_seconds = 0.5

    def _should_process(self, path: str) -> bool:
        """Check if this event should be processed"""
        # Only .py files
        if not path.endswith('.py'):
            return False

        # Skip common junk
        skip_patterns = ['__pycache__', '.venv', 'venv', '.git', '.tox', 'node_modules']
        if any(p in path for p in skip_patterns):
            return False

        # Debounce (editors fire multiple events per save)
        now = time.time()
        if path in self._debounce:
            if now - self._debounce[path] < self._debounce_seconds:
                return False
        self._debounce[path] = now

        return True

    def on_modified(self, event):
        if event.is_directory:
            return
        if self._should_process(event.src_path):
            path = Path(event.src_path)
            logger.info(f"MODIFIED: {path.name}")
            self.state.recent_changes.append(
                FileChange(path=path, timestamp=datetime.now(), event_type='modified')
            )
            self.on_change(path)

    def on_created(self, event):
        if event.is_directory:
            return
        if self._should_process(event.src_path):
            path = Path(event.src_path)
            logger.info(f"CREATED: {path.name}")
            self.state.recent_changes.append(
                FileChange(path=path, timestamp=datetime.now(), event_type='created')
            )
            self.on_change(path)


class HarnessCore:
    """Main harness daemon"""

    def __init__(self, watch_dirs: list[Path]):
        self.state = HarnessState(watch_dirs=watch_dirs)
        self.observer = Observer()
        self.handler = PythonFileHandler(self.state, self._on_file_change)

    def register_validator(self, validator: Callable[[Path], tuple[bool, str]]):
        """
        Register a validation function.
        Validator signature: (path: Path) -> (passed: bool, message: str)
        """
        self.state.validators.append(validator)
        logger.info(f"Registered validator: {validator.__name__}")

    def _on_file_change(self, path: Path):
        """Called when a .py file changes"""
        self.state.files_checked += 1

        if not self.state.validators:
            logger.warning('No validators registered')
            return

        all_passed = True
        for validator in self.state.validators:
            try:
                passed, message = validator(path)
                if passed:
                    logger.info(f"  ✓ {validator.__name__}: {message}")
                else:
                    logger.error(f"  ✗ {validator.__name__}: {message}")
                    all_passed = False
            except Exception as e:
                logger.error(f"  ✗ {validator.__name__} EXCEPTION: {e}")
                all_passed = False

        if all_passed:
            self.state.validations_passed += 1
        else:
            self.state.validations_failed += 1

    def start(self):
        """Start watching directories"""
        self.state.running = True

        for watch_dir in self.state.watch_dirs:
            if watch_dir.exists():
                self.observer.schedule(self.handler, str(watch_dir), recursive=True)
                logger.info(f"Watching: {watch_dir}")
            else:
                logger.error(f"Directory not found: {watch_dir}")

        self.observer.start()
        logger.info('Harness started. Watching for .py changes...')
        logger.info(f"Validators registered: {len(self.state.validators)}")
        logger.info('Press Ctrl+C to stop.\n')

    def stop(self):
        """Stop watching"""
        self.state.running = False
        self.observer.stop()
        self.observer.join()
        logger.info('Harness stopped.')
        logger.info(f"Files checked: {self.state.files_checked}")
        logger.info(f"Passed: {self.state.validations_passed}")
        logger.info(f"Failed: {self.state.validations_failed}")

    def run_forever(self):
        """Run until interrupted"""
        self.start()
        try:
            while self.state.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


# Placeholder validator for standalone testing

def dummy_validator(path: Path) -> tuple[bool, str]:
    """Always passes - placeholder for testing watcher works"""
    return (True, 'dummy check passed')


# CLI entry point

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print('Usage: python -m harness.watcher /path/to/watch [/another/path ...]')
        print('\nExample:')
        print('  python -m harness.watcher ./orchestrator ./recorder ./granularize')
        sys.exit(1)

    watch_paths = [Path(p).resolve() for p in sys.argv[1:]]

    harness = HarnessCore(watch_dirs=watch_paths)
    harness.register_validator(dummy_validator)
    harness.run_forever()
