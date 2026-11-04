#!/usr/bin/env python3
"""load_recorder_trial.py — the A proof, run by a script instead of a person (owner 2026-10-06).

    load_recorder_trial.py --target T --sample S   # replay a recorded eslogger sample (no root)
    load_recorder_trial.py --target T --live       # start eslogger (sudo -n), run the target + a non-target

Asserts on the SAME reducer the launch uses (load_proof.LoadProof):
  1. the target run (`python3 -m charlie_work.the_gang_runs_for_office`) is a target run, and every target
     `.py` it opened is proven — on that pid;
  2. a non-target `python3 -m json.tool` stays dark (not a run, proves nothing);
  3. a process that only opens target files without exec'ing a target module proves nothing (editor/linter);
  4. a fork of a target run inherits it;
  5. an edit after the load makes that module's proof stale (hash re-check, as the daemon does).
Exit 0 only when every assertion passes; each failure is printed.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from load_recorder import LoadProof  # noqa: E402

TARGET_CMD = ['-m', 'charlie_work.the_gang_runs_for_office']


def _ev(kind, body, pid, t='2026-10-06T00:00:00Z', exe='/usr/bin/python3'):
    return {'time': t, 'process': {'audit_token': {'pid': pid}, 'executable': {'path': exe}}, 'event': {kind: body}}


def _exec(pid, args, cwd):
    return _ev('exec', {'args': args, 'cwd': {'path': cwd}, 'target': {'audit_token': {'pid': pid}}}, pid)


def _open(pid, path):
    return _ev('open', {'file': {'path': path}}, pid)


def canned_cases(repo: Path, fails: list) -> None:
    """Cases 2-5 on canned events (no root, no process)."""
    files = sorted(p for p in repo.rglob('*.py'))
    one = files[0]
    p = LoadProof(repo)
    p.feed(_exec(9001, ['python3', '-m', 'json.tool'], str(repo)))
    for f in files:
        p.feed(_open(9001, str(f)))
    if p.runs or p.loaded:
        fails.append(f"2: non-target `-m json.tool` lit something: runs={list(p.runs)} loaded={list(p.loaded)}")
    p = LoadProof(repo)
    p.feed(_exec(9002, ['/usr/bin/vim', str(one)], str(repo)))
    p.feed(_open(9002, str(one)))
    p.feed(_open(9003, str(one)))                         # a process never seen exec'ing (a scanner)
    if p.loaded:
        fails.append(f"3: an editor / never-exec'd process proved {list(p.loaded)}")
    p = LoadProof(repo)
    p.feed(_exec(9004, ['python3', *TARGET_CMD], str(repo)))
    p.feed(_ev('fork', {'child': {'audit_token': {'pid': 9005}}}, 9004))
    p.feed(_open(9005, str(one)))
    if one.relative_to(repo).as_posix() not in p.loaded:
        fails.append("4: a fork of a target run did not inherit it")
    # 5: stale after edit — on a throwaway copy, never the target
    tmp = Path(tempfile.mkdtemp(prefix='lpc_'))
    try:
        shutil.copytree(repo, tmp / 'r', ignore=shutil.ignore_patterns('__pycache__', '.coderadar'))
        r = (tmp / 'r').resolve()
        f = sorted(r.rglob('*.py'))[0]
        p = LoadProof(r)
        p.feed(_exec(9006, ['python3', *TARGET_CMD], str(r)))
        p.feed(_open(9006, str(f)))
        rec = p.loaded.get(f.relative_to(r).as_posix())
        f.write_text(f.read_text() + '\n# edited\n')
        now = f"sha256:{hashlib.sha256(f.read_bytes()).hexdigest()}"
        if not rec or rec['sha256'] == now:
            fails.append("5: an edit after the load did not make the proof stale")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def target_run_misses(doc: dict, repo: Path, fails: list) -> None:
    """Case 1 on a recorder document (replay or live)."""
    runs = [r for r in doc.get('runs') or [] if r.get('node') == 'charlie_work/the_gang_runs_for_office.py']
    pids = {r['pid'] for r in runs}
    want = {p.relative_to(repo).as_posix() for p in repo.rglob('*.py')}
    got = {rel for rel, rec in (doc.get('loaded') or {}).items() if rec.get('pid') in pids}
    if runs and got != want:
        fails.append(f"1: pong pid(s) {sorted(pids)} proved {len(got)}/{len(want)} modules; "
                     f"missing {sorted(want - got)}")
    elif not runs:
        fails.append(f"1: the pong run was not seen as a target run (runs={doc.get('runs')})")
    stray = [r for r in doc.get('runs') or [] if r.get('pid') not in pids and 'json' in (r.get('cmd') or '')]
    if stray:
        fails.append(f"2 (live): json.tool was taken for a target run: {stray}")


def run_recorder(repo: Path, args: list, timeout: float) -> dict:
    out = Path(tempfile.mkdtemp(prefix='lpc_out_')) / 'load_proof.json'
    cmd = [sys.executable, str(Path(__file__).parent / 'load_recorder.py'), '--target', str(repo), '--out', str(out), *args]
    rec = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
    return {'proc': rec, 'out': out, 'timeout': timeout}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--sample')
    g.add_argument('--live', action='store_true')
    ap.add_argument('--python', default='python3', help='interpreter that runs the target in --live')
    a = ap.parse_args()
    repo = Path(a.target).resolve()
    fails: list = []
    canned_cases(repo, fails)

    if a.sample:
        r = run_recorder(repo, ['--replay', a.sample], 120)
        r['proc'].wait(timeout=120)
        doc = json.loads(r['out'].read_text())
    else:
        r = run_recorder(repo, [], 60)
        deadline = time.time() + 10
        while time.time() < deadline:            # wait for eslogger to be up (first doc written + alive)
            if r['out'].exists() and json.loads(r['out'].read_text() or '{}').get('recorder', {}).get('alive'):
                break
            time.sleep(0.2)
        time.sleep(1.5)
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
        pong = subprocess.Popen([a.python, '-B', *TARGET_CMD], cwd=repo, env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        other = subprocess.Popen([a.python, '-B', '-m', 'json.tool', '--help'], cwd=repo, env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(4)
        pong.terminate(); other.wait(timeout=10)
        try:
            pong.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pong.kill()
        time.sleep(1.5)
        r['proc'].terminate()
        r['proc'].wait(timeout=15)
        doc = json.loads(r['out'].read_text())
        if not doc.get('recorder', {}).get('events'):
            fails.append(f"live: eslogger produced no events — {doc.get('recorder', {}).get('reason')}")
    target_run_misses(doc, repo, fails)

    print(f"load proof check ({'replay ' + a.sample if a.sample else 'live eslogger'}): "
          f"{doc.get('recorder', {}).get('events', 0)} events · runs {[(x['pid'], x['node']) for x in doc.get('runs') or []]}"
          f" · proven {len(doc.get('loaded') or {})}")
    for f in fails:
        print('  ✗', f)
    print('PASS' if not fails else f'FAIL ({len(fails)})')
    return 0 if not fails else 1


if __name__ == '__main__':
    sys.exit(main())
