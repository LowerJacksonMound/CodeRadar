"""
GRANULARIZE HARNESS - Unified Monitor
Combines file watcher, CRC, mypy, and contract monitoring.
Single terminal display.
"""

import json
import time
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Any, Optional
from dataclasses import dataclass, field

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

# Watcher requires watchdog (optional dependency)
# FIX_54 (2026-09-17): the optional-import pattern, typed. The name is bound either to the class
# or to None, so it is declared Any once and the try/except keeps its exact runtime behaviour.
try:
    from .watcher import HarnessCore as _HarnessCore, HarnessState as _HarnessState
    WATCHER_AVAILABLE = True
except ImportError:
    _HarnessCore = None   # type: ignore[assignment,misc]
    _HarnessState = None  # type: ignore[assignment,misc]
    WATCHER_AVAILABLE = False
HarnessCore: Any = _HarnessCore
HarnessState: Any = _HarnessState

from .crc_engine import CRCEngine, init_crc_validator, crc_validator
from .mypy_validator import MypyEngine, init_mypy_validator, mypy_validator
from .contracts import init_contract_logging, get_recent_violations, ContractViolation
from .io_tracker import scan_io_functions

logging.basicConfig(
    level=logging.WARNING,
    format='%(message)s',
)


# ---------------------------------------------------------------------------
# Violation log helpers
# ---------------------------------------------------------------------------

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


def init_violation_log(log_path: Path) -> Path:
    """Initialize violation log file."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not log_path.exists():
        log_path.write_text('')
    return log_path


def log_violation(log_path: Path, validator: str, file: str, message: str):
    """Append a violation to the log file."""
    entry = {
        'timestamp': datetime.now().isoformat(),
        'validator': validator,
        'file': file,
        'message': message,
    }
    with open(log_path, 'a') as f:
        f.write(json.dumps(entry) + '\n')


def get_violation_history(log_path: Path, n: int = 50) -> list[dict]:
    """Get last n violations from log."""
    if not log_path.exists():
        return []

    lines = log_path.read_text().strip().split('\n')
    lines = [l for l in lines if l.strip()]

    violations = []
    for line in lines[-n:]:
        try:
            violations.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return violations


# ---------------------------------------------------------------------------
# Monitor state
# ---------------------------------------------------------------------------

@dataclass
class MonitorState:
    """State for the unified monitor display"""

    running: bool = False
    start_time: Optional[datetime] = None

    # Watch info
    watch_dirs: list[Path] = field(default_factory=list)

    # Validator stats
    files_checked: int = 0
    crc_passed: int = 0
    crc_failed: int = 0
    mypy_passed: int = 0
    mypy_failed: int = 0

    # Recent events (rolling window)
    recent_events: list[str] = field(default_factory=list)
    max_events: int = 10

    # Last violation
    last_violation: Optional[str] = None
    last_violation_time: Optional[datetime] = None

    # Contract violations
    contract_violations: int = 0

    def add_event(self, event: str):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.recent_events.append(f"[{timestamp}] {event}")
        if len(self.recent_events) > self.max_events:
            self.recent_events.pop(0)


# ---------------------------------------------------------------------------
# Unified harness
# ---------------------------------------------------------------------------

class UnifiedHarness:
    """
    Unified harness combining all validators with rich display.
    """

    def __init__(
        self,
        watch_dirs: list[Path],
        baseline_path: Optional[Path] = None,
        contract_log_path: Optional[Path] = None,
        violation_log_path: Optional[Path] = None,
        no_mypy: bool = False,
    ):
        self.console = Console()
        self.state = MonitorState(watch_dirs=watch_dirs)
        self.no_mypy = no_mypy

        # File watcher core
        self.watcher = HarnessCore(watch_dirs=watch_dirs)

        # Violation log
        self.violation_log_path = violation_log_path or Path.home() / '.harness' / 'violations.jsonl'
        init_violation_log(self.violation_log_path)
        self.state.add_event(f"Violations log: {self.violation_log_path}")

        # CRC engine
        self.crc_engine = None
        if baseline_path and baseline_path.exists():
            self.crc_engine = CRCEngine()
            self.crc_engine.load_baseline(baseline_path)
            self.state.add_event(f"CRC baseline loaded: {baseline_path.name}")
        else:
            self.state.add_event('CRC: No baseline (create with --create-baseline)')

        # mypy engine
        self.mypy_engine = MypyEngine()
        if self.no_mypy:
            self.state.add_event('mypy validator [red]DISABLED[/red]')
        else:
            self.state.add_event('mypy validator ready')

        # Contract logging
        self.contract_log_path = contract_log_path or Path.home() / '.harness' / 'contracts.log'
        init_contract_logging(self.contract_log_path)
        self.state.add_event(f"Contracts log: {self.contract_log_path}")

        # Register the combined validator with the watcher
        self.watcher.state.validators.append(self._combined_validator)

    def _combined_validator(self, path: Path) -> tuple[bool, str]:
        """Combined validator that runs CRC and mypy"""
        self.state.files_checked += 1

        results = []
        all_passed = True

        # CRC check
        if self.crc_engine:
            crc_passed, crc_msg = self.crc_engine.check_file(path)
            if crc_passed:
                self.state.crc_passed += 1
                results.append('CRC:✓')
            else:
                self.state.crc_failed += 1
                results.append('CRC:✗')
                all_passed = False
                violation_msg = f"{path.name} - {crc_msg}"
                self.state.last_violation = f"CRC: {violation_msg}"
                self.state.last_violation_time = datetime.now()

                log_violation(self.violation_log_path, 'CRC', str(path), crc_msg)

        # mypy check
        if not self.no_mypy:
            mypy_passed, mypy_msg = self.mypy_engine.check_file(path)
            if mypy_passed:
                self.state.mypy_passed += 1
                results.append('mypy:✓')
            else:
                self.state.mypy_failed += 1
                results.append('mypy:✗')
                all_passed = False
                violation_msg = f"{path.name} - {mypy_msg}"
                self.state.last_violation = f"mypy: {violation_msg}"
                self.state.last_violation_time = datetime.now()

                log_violation(self.violation_log_path, 'mypy', str(path), mypy_msg)

        # Summary event
        status = '✓' if all_passed else '✗'
        self.state.add_event(f"{status} {path.name} [{', '.join(results)}]")

        combined_msg = ' | '.join(results)
        return (all_passed, combined_msg)

    def scan_and_exit(self):
        """Scan all files in watch_dirs once and exit."""
        self.console.print(f"[cyan]Starting single scan of {len(self.state.watch_dirs)} directories...[/cyan]")

        for watch_dir in self.state.watch_dirs:
            if not watch_dir.exists():
                self.console.print(f"[red]Error: Directory not found: {watch_dir}[/red]")
                continue

            self.console.print(f"Scanning: {watch_dir}")

            # Validate every .py file
            py_files = list(_scan_scope().iter_live_py(watch_dir))  # whitelist 2026-09-05; the ONE contained walk, FIX_15
            if not py_files:
                self.console.print('[dim]  No .py files found.[/dim]')
                continue

            for path in py_files:
                self._combined_validator(path)

        self.console.print('\n[bold cyan]Scan Complete[/bold cyan]')
        self.console.print(f"Files checked: {self.state.files_checked}")

        crc_report = f"CRC: {self.state.crc_passed} pass / {self.state.crc_failed} fail"
        if self.state.crc_failed > 0:
            self.console.print(f"[red]{crc_report}[/red]")
        else:
            self.console.print(f"[green]{crc_report}[/green]")

        mypy_report = f"mypy: {self.state.mypy_passed} pass / {self.state.mypy_failed} fail"
        if self.state.mypy_failed > 0:
            self.console.print(f"[red]{mypy_report}[/red]")
        else:
            self.console.print(f"[green]{mypy_report}[/green]")

        if self.state.crc_failed == 0 and self.state.mypy_failed == 0:
            self.console.print('\n[bold green]✓ All checks passed.[/bold green]')
        else:
            self.console.print('\n[bold red]✗ Some checks failed.[/bold red]')

    def export_io_log(self, output_path: Path) -> Path:
        """
        Export a combined I/O + violations report as a single JSON file.
        Includes: validator pass/fail tallies, every logged violation,
        and the full I/O function scan for each watched directory.
        """
        # Everything ever logged
        violations = get_violation_history(self.violation_log_path, n=10000)

        # Fresh I/O scan of every watch dir
        io_scans = {}
        for d in self.state.watch_dirs:
            if d.exists():
                io_scans[str(d)] = scan_io_functions(d)

        report = {
            'generated': datetime.now().isoformat(),
            'summary': {
                'files_checked': self.state.files_checked,
                'crc_passed': self.state.crc_passed,
                'crc_failed': self.state.crc_failed,
                'mypy_passed': self.state.mypy_passed,
                'mypy_failed': self.state.mypy_failed,
                'contract_violations': self.state.contract_violations,
            },
            'violations': violations,
            'io_scan': io_scans,
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, default=str))
        self.console.print(f"[green]✓ I/O log exported → {output_path}[/green]")
        return output_path

    def _check_contracts(self):
        """Check for recent contract violations"""
        violations = get_recent_violations(self.contract_log_path, n=1)
        if violations:
            v = violations[0]
            self.state.contract_violations = len(get_recent_violations(self.contract_log_path, n=100))
            self.state.last_violation = f"Contract: {v.function} - {v.violation_type}"
            self.state.last_violation_time = datetime.fromisoformat(v.timestamp)

    def _make_display(self) -> Panel:
        """Generate the rich display panel"""
        # Uptime
        uptime = ''
        if self.state.start_time:
            delta = datetime.now() - self.state.start_time
            uptime = f"Uptime: {int(delta.total_seconds())}s"

        # Status table
        status_table = Table(show_header=False, box=None, padding=(0, 2))
        status_table.add_column('Label', style='cyan')
        status_table.add_column('Value', style='white')

        status_table.add_row('Status', '[green]RUNNING[/green]' if self.state.running else '[red]STOPPED[/red]')
        status_table.add_row('Watching', str(len(self.state.watch_dirs)) + ' directories')
        status_table.add_row('Files Checked', str(self.state.files_checked))
        status_table.add_row('', '')

        # Validators table
        validators_table = Table(show_header=True, box=None)
        validators_table.add_column('Validator', style='cyan')
        validators_table.add_column('Pass', style='green', justify='right')
        validators_table.add_column('Fail', style='red', justify='right')

        validators_table.add_row(
            'CRC (frozen)',
            str(self.state.crc_passed),
            str(self.state.crc_failed),
        )
        validators_table.add_row(
            'mypy (types)',
            str(self.state.mypy_passed),
            str(self.state.mypy_failed),
        )
        validators_table.add_row(
            'Contracts',
            '-',
            str(self.state.contract_violations),
        )

        # Last violation
        violation_text = ''
        if self.state.last_violation:
            age = ''
            if self.state.last_violation_time:
                delta = datetime.now() - self.state.last_violation_time
                age = f" ({int(delta.total_seconds())}s ago)"
            violation_text = f"[red]{self.state.last_violation}{age}[/red]"
        else:
            violation_text = '[green]None[/green]'

        # Recent events
        events_text = '\n'.join(self.state.recent_events[-8:]) if self.state.recent_events else '[dim]No events yet[/dim]'

        # Compose panel content
        content = Text()
        content.append('════════════════════════════════════════════════════════\n', style='cyan')
        content.append('  GRANULARIZE HARNESS', style='bold cyan')
        content.append(f"  {uptime}\n", style='dim')
        content.append('════════════════════════════════════════════════════════\n\n', style='cyan')

        # Simple text layout
        output = []
        output.append('─── STATUS ───')
        output.append(f"  Running:      {'[green]YES[/green]' if self.state.running else '[red]NO[/red]'}")
        output.append(f"  Watching:     {len(self.state.watch_dirs)} directories")
        output.append(f"  Files Checked: {self.state.files_checked}")
        output.append('')
        output.append('─── VALIDATORS ───')
        output.append(f"  CRC (frozen): [green]{self.state.crc_passed} pass[/green] / [red]{self.state.crc_failed} fail[/red]")
        output.append(f"  mypy (types): [green]{self.state.mypy_passed} pass[/green] / [red]{self.state.mypy_failed} fail[/red]")
        output.append(f"  Contracts:    [red]{self.state.contract_violations} violations[/red]")
        output.append('')
        output.append('─── LAST VIOLATION ───')
        output.append(f"  {violation_text}")
        output.append('')
        output.append('─── RECENT EVENTS ───')
        for event in self.state.recent_events[-6:]:
            output.append(f"  {event}")
        output.append('')
        output.append('[dim]Press Ctrl+C to stop[/dim]')

        return Panel(
            '\n'.join(output),
            title='[bold cyan]GRANULARIZE HARNESS[/bold cyan]',
            border_style='cyan',
        )

    def run(self):
        """Run the harness with live display"""
        self.state.running = True
        self.state.start_time = datetime.now()

        # Start the file watcher
        self.watcher.start()
        self.state.add_event('Harness started')

        try:
            with Live(self._make_display(), refresh_per_second=2, console=self.console) as live:
                while self.state.running:
                    # Poll contract log
                    self._check_contracts()

                    # Refresh display
                    live.update(self._make_display())
                    time.sleep(0.5)

        except KeyboardInterrupt:
            pass
        finally:
            self.state.running = False
            self.watcher.stop()
            self.console.print('\n[yellow]Harness stopped.[/yellow]')
            self.console.print(f"Files checked: {self.state.files_checked}")
            self.console.print(f"CRC: {self.state.crc_passed} pass / {self.state.crc_failed} fail")
            self.console.print(f"mypy: {self.state.mypy_passed} pass / {self.state.mypy_failed} fail")
            self.console.print(f"[dim]Violation history: {self.violation_log_path}[/dim]")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='GRANULARIZE HARNESS - Runtime validation monitor')
    parser.add_argument('watch_dirs', nargs='+', help='Directories to watch')
    parser.add_argument('--baseline', '-b', type=Path, help='CRC baseline file')
    parser.add_argument('--contract-log', '-c', type=Path, help='Contract violation log path')
    parser.add_argument('--violation-log', '-v', type=Path, help='CRC/mypy violation log path')
    parser.add_argument('--create-baseline', '-B', type=Path, help='Create baseline at this path and exit')
    parser.add_argument('--show-violations', '-V', type=int, metavar='N', help='Show last N violations and exit')
    parser.add_argument('--scan-and-exit', action='store_true', help='Scan target directories once and exit')
    parser.add_argument('--no-mypy', action='store_true', help='Disable mypy validation')
    parser.add_argument('--export-log', '-E', type=Path, metavar='PATH',
                        help='Export combined I/O + violations report to PATH (JSON)')

    args = parser.parse_args()

    # Show violations mode
    if args.show_violations:
        log_path = args.violation_log or Path.home() / '.harness' / 'violations.jsonl'
        console = Console()

        if not log_path.exists():
            console.print(f"[yellow]No violation log found at {log_path}[/yellow]")
            return

        violations = get_violation_history(log_path, args.show_violations)

        if not violations:
            console.print('[green]No violations recorded.[/green]')
            return

        console.print(f"[cyan]Last {len(violations)} violations from {log_path}:[/cyan]\n")

        for v in violations:
            ts = v.get('timestamp', '?')[:19]
            validator = v.get('validator', '?')
            file = Path(v.get('file', '?')).name
            msg = v.get('message', '?')[:80]

            color = 'red' if validator == 'CRC' else 'yellow'
            console.print(f"[dim]{ts}[/dim] [{color}]{validator}[/{color}] {file}: {msg}")

        return

    watch_paths = [Path(p).resolve() for p in args.watch_dirs]

    # Create baseline mode
    if args.create_baseline:
        console = Console()
        console.print('[cyan]Creating CRC baseline...[/cyan]')
        engine = CRCEngine()
        engine.create_baseline(watch_paths, args.create_baseline)
        console.print(f"[green]✓ Baseline created: {args.create_baseline}[/green]")
        console.print("\nTo freeze functions, edit the baseline.json and add to 'frozen' list:")
        console.print('  "frozen": ["path/to/file.py::function_name"]')
        return

    # Normal run
    harness = UnifiedHarness(
        watch_dirs=watch_paths,
        baseline_path=args.baseline,
        contract_log_path=args.contract_log,
        violation_log_path=args.violation_log,
        no_mypy=args.no_mypy,
    )

    if args.scan_and_exit:
        harness.scan_and_exit()
    else:
        harness.run()

    # Optional export after the run
    if args.export_log:
        harness.export_io_log(args.export_log)


if __name__ == '__main__':
    main()
