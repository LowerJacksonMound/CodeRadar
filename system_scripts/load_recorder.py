#!/usr/bin/env python3
"""load_recorder.py — target-module LOAD PROOF from eslogger (owner 2026-10-06, narrow amendment).

eslogger runs ONLY as a file-load monitor: proof that a running target process — however it was started
(`python x.py`, `python -m pkg.mod`, an IDE, a relative path) — loaded each target module. lsof stays the
launch tracer; `--tracer eslogger` stays refused (launch.sh).

The rule (owner + review 2026-10-06, from the real sample: pid 14399 `python3 -m
charlie_work.the_gang_runs_for_office` opened all 12 target .py files):
  - a process is a TARGET RUN when its `exec` args + cwd resolve to a target module (the same resolver as
    the process scan, C), or when it was forked from a target run;
  - every target `.py`, or `.pyc` under a target `__pycache__/`, that a target run opens is LOADED — its
    source is hashed at that open (a later edit makes the proof stale; the daemon re-checks the hash);
  - a process that only opens target files and never execs a target module (an editor, a linter,
    CodeRadar's own scanners) proves nothing;
  - a target already running before the recorder started stays "seen, not proof" (its imports were missed).

Runs as the USER, reading eslogger's JSON lines from a pipe: `sudo -n eslogger …` is the only root process
(started here as a child, needs launch.sh's one `sudo -v`). When this process exits, the pipe closes and
eslogger dies on its next write — nothing is left running as root.

    load_recorder.py --target T --out F              # start eslogger (sudo -n) and record
    load_recorder.py --target T --out F --replay E   # replay a saved eslogger JSON-lines file (no root)
"""
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import IO, Any, Dict, List, Optional

ESLOGGER = "/usr/bin/eslogger"
EVENTS = ("exec", "fork", "exit", "open")
WRITE_EVERY_S = 2.0   # the heartbeat: the daemon reads `recorder.alive` + `updated` from this file


def module_token(tokens: List[str]) -> Optional[str]:
    """The module a `python … -m pkg.mod …` command runs — `-m pkg.mod` or the joined `-mpkg.mod` form —
    or None. Only the first `-m` counts: what follows it is the module's own argv."""
    for i, tok in enumerate(tokens):
        if tok == '-m':
            return tokens[i + 1] if i + 1 < len(tokens) else None
        if tok.startswith('-m') and len(tok) > 2 and not tok.startswith('--'):
            return tok[2:]
    return None


def resolve_run_target(rel: str, bases: List[Path], repo_path: Path, module: bool) -> Optional[Path]:
    """The file under `repo_path` that `rel` names when read from each base in turn (the process's cwd
    first, then the repo root). A module resolves to `pkg/mod.py`, else to `pkg/mod/__main__.py` (what
    `python -m pkg` runs). None when no base gives an existing file inside the repo."""
    if module:
        parts = Path(*rel.split('.'))
        rels = [parts.with_suffix('.py'), parts / '__main__.py']
    else:
        rels = [Path(rel)]
    for base in bases:
        for r in rels:
            cand = (base / r).resolve()
            if cand.is_file():
                try:
                    cand.relative_to(repo_path)
                except ValueError:
                    continue
                return cand
    return None


def run_target_of(args: List[str], cwd: Optional[str], repo: Path) -> Optional[Path]:
    """The target module a command line runs — `-m pkg.mod`, else the first `.py` argument — read from the
    process's cwd, then the repo root. None: not a target run."""
    bases = ([Path(cwd)] if cwd else []) + [repo]
    mod = module_token(args)
    if mod:
        return resolve_run_target(mod, bases, repo, module=True)
    for tok in args[1:]:
        if tok.endswith('.py'):
            return resolve_run_target(tok, bases, repo, module=False)
    return None


def is_python(exe: Optional[str], args: List[str]) -> bool:
    """An interpreter exec: the executable (`python3.14`, framework `…/MacOS/Python`) or argv[0] is Python."""
    names = [Path(exe).name if exe else '', Path(args[0]).name if args else '']
    return any(n.lower().startswith('python') for n in names)


def source_of(path: Path, repo: Path) -> Optional[Path]:
    """The target `.py` a loaded file stands for: itself, or the source of `pkg/__pycache__/mod.cpython-*.pyc`.
    None for anything outside the repo or of another kind."""
    if not path.is_relative_to(repo):
        return None
    if path.suffix == '.py':
        return path
    if path.suffix == '.pyc' and path.parent.name == '__pycache__':
        src = path.parent.parent / (path.name.split('.')[0] + '.py')
        return src if src.is_file() else None
    return None


def _event(line: str) -> Dict[str, Any]:
    """One eslogger JSON line; a torn or partial line (eslogger killed mid-write) reads as no event."""
    try:
        ev = json.loads(line)
    except ValueError:
        ev = {}
    return ev if isinstance(ev, dict) else {}


def _pid(proc: Dict[str, Any]) -> Optional[int]:
    return ((proc or {}).get('audit_token') or {}).get('pid')


class LoadProof:
    """Reduces eslogger events to: target runs (pid → what it runs) and loaded target modules (rel → hash)."""

    def __init__(self, repo: Path):
        self.repo = repo.resolve()
        self.runs: Dict[int, Dict[str, Any]] = {}     # pid -> {node, cmd, cwd, via, started, exited}
        self.loaded: Dict[str, Dict[str, Any]] = {}   # 'pkg/mod.py' -> {sha256, pid, at}
        self.events = 0

    def feed(self, ev: Dict[str, Any]) -> bool:
        """One eslogger event. True when the proof changed."""
        self.events += 1
        body = ev.get('event') or {}
        if 'exec' in body:
            x = body['exec']
            tgt = x.get('target') or {}
            pid = _pid(tgt)
            if pid is None:
                return False
            args = list(x.get('args') or [])
            exe = tgt.get('executable')
            exe = exe.get('path') if isinstance(exe, dict) else exe
            # only a PYTHON exec runs a module — `vim x.py` / `ruff x.py` name a target file and prove nothing
            hit = (run_target_of(args, (x.get('cwd') or {}).get('path'), self.repo)
                   if is_python(exe, args) else None)
            if hit is None:
                return self.runs.pop(pid, None) is not None        # a target run exec'd something else
            self.runs[pid] = {'node': hit.relative_to(self.repo).as_posix(), 'cmd': ' '.join(x.get('args') or []),
                              'cwd': (x.get('cwd') or {}).get('path'), 'via': 'exec',
                              'started': ev.get('time'), 'exited': None}
            return True
        if 'fork' in body:
            parent, child = _pid(ev.get('process') or {}), _pid((body['fork'] or {}).get('child') or {})
            if parent in self.runs and child is not None:
                self.runs[child] = {**self.runs[parent], 'via': f'fork of {parent}', 'started': ev.get('time'),
                                    'exited': None}
                return True
            return False
        if 'exit' in body:
            pid = _pid(ev.get('process') or {})
            if pid in self.runs and self.runs[pid].get('exited') is None:
                self.runs[pid]['exited'] = ev.get('time')
                return True
            return False
        if 'open' in body:
            pid = _pid(ev.get('process') or {})
            if pid not in self.runs:
                return False
            path = ((body['open'] or {}).get('file') or {}).get('path')
            src = source_of(Path(path), self.repo) if path else None
            if src is None:
                return False
            rel = src.relative_to(self.repo).as_posix()
            try:
                digest = f"sha256:{hashlib.sha256(src.read_bytes()).hexdigest()}"
            except OSError:
                return False
            prev = self.loaded.get(rel)
            if prev and prev['sha256'] == digest:
                return False
            self.loaded[rel] = {'sha256': digest, 'pid': pid, 'at': ev.get('time')}
            return True
        return False

    def wanted(self, line: str, esc_repo: str) -> bool:
        """Cheap pre-check before json.loads — eslogger writes ~470 events/s, almost all opens elsewhere."""
        return esc_repo in line or '"exec":' in line or '"fork":' in line or ('"exit":' in line and bool(self.runs))

    def doc(self, recorder: Dict[str, Any]) -> Dict[str, Any]:
        return {'target': str(self.repo), 'recorder': {**recorder, 'events': self.events},
                'runs': [{'pid': p, **r} for p, r in sorted(self.runs.items())],
                'loaded': dict(sorted(self.loaded.items())),
                'updated': time.strftime('%Y-%m-%dT%H:%M:%S')}


def _heartbeat(out: Path, proof: 'LoadProof', recorder: Dict[str, Any], halt: threading.Event) -> None:
    """Rewrites the file every WRITE_EVERY_S while the recorder lives — `updated` is the daemon's liveness
    reading, and a quiet eslogger stream (no target activity) must not read as a dead recorder."""
    while not halt.wait(WRITE_EVERY_S):
        write_doc(out, proof.doc(recorder))


def write_doc(out: Path, doc: Dict[str, Any]) -> None:
    tmp = out.with_suffix('.tmp')
    tmp.write_text(json.dumps(doc, indent=1))
    os.replace(tmp, out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--target', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--replay', help='an eslogger JSON-lines file to replay instead of starting eslogger')
    a = ap.parse_args()
    repo, out = Path(a.target).resolve(), Path(a.out)
    proof = LoadProof(repo)
    esc_repo = json.dumps(str(repo))[1:-1].replace('/', '\\/')
    recorder: Dict[str, Any] = {'alive': False, 'pid': os.getpid(), 'started_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
                                'reason': None}
    child = None
    stream: Optional[IO[str]]
    if a.replay:
        stream = open(a.replay, encoding='utf-8', errors='replace')
        recorder.update(alive=True, mode='replay')
    else:
        child = subprocess.Popen(['sudo', '-n', ESLOGGER, *EVENTS], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, bufsize=1)
        stream = child.stdout
        recorder.update(alive=True, mode='eslogger')
    stop = {'now': False}

    def _stop(signum, _frame):
        stop['now'] = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    write_doc(out, proof.doc(recorder))
    halt = threading.Event()
    threading.Thread(target=_heartbeat, args=(out, proof, recorder, halt), daemon=True).start()
    try:
        for line in stream or ():
            if stop['now']:
                break
            if not proof.wanted(line, esc_repo):
                proof.events += 1          # an open elsewhere on the machine — counted, never parsed
            elif proof.feed(_event(line)):
                write_doc(out, proof.doc(recorder))
    finally:
        halt.set()
        recorder['alive'] = False
        if child is not None:
            rc = child.poll()
            err = (child.stderr.read() if rc is not None and child.stderr else '') or ''
            recorder['reason'] = ('stopped' if stop['now'] or rc is None else
                                  f"eslogger exited {rc}: {err.strip()[-300:] or 'no message'}"
                                  + (' — needs `sudo -v` first' if 'password' in err.lower() else '')
                                  + (' — grant Full Disk Access to the terminal' if 'TCC' in err or 'Full Disk' in err
                                     or 'not permitted' in err.lower() else ''))
            if stream:
                stream.close()   # eslogger (root) dies on its next write: nothing is left running as root
        else:
            recorder['reason'] = 'replay finished'
        write_doc(out, proof.doc(recorder))
    return 0 if recorder['reason'] in ('stopped', 'replay finished') else 1


if __name__ == '__main__':
    sys.exit(main())
