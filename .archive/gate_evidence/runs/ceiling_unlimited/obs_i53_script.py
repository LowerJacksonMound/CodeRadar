#!/usr/bin/env python3
"""I-53 live observation: two pytest processes, the SAME relative test path, different cwds.

One is started inside the target, one inside a decoy tree that carries the same relative path.
Both are alive at the same moment. The band must carry the first and not the second.
The BEFORE reading is taken with the lane's own base copy of the matcher, on the SAME two real
pids and command lines, so the two readings differ only in the code under proof.
"""
import importlib.util, json, os, subprocess, sys, time
from pathlib import Path

ROOT = Path("/Users/dev/Desktop/CODE_RADAR_REFURBISH_copy2")
TARGET = Path("/Users/dev/Desktop/ceiling_unlimited")
DECOY = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/private/tmp/decoy_tree")
REL = "colorama/tests/ceiling_unlimited_test.py"
PY = str(ROOT / ".venv_new" / "bin" / "python3")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def start(cwd):
    env = {**os.environ, "CEILING_UNLIMITED_DWELL": "150", "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.Popen([PY, "-m", "pytest", REL, "-p", "no:cacheprovider", "-q"],
                            cwd=str(cwd), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


inside = start(TARGET)
outside = start(DECOY)
time.sleep(6)

sys.path.insert(0, str(ROOT / "system_scripts"))
live = load(ROOT / "system_scripts" / "test_runner_tracker.py", "trt_live")
base = load(ROOT / ".archive" / "lane_base" / "system_scripts" / "test_runner_tracker.py", "trt_base")

ps = live.list_python_processes()
mine = [(p, c) for p, c in ps if p in (inside.pid, outside.pid)]
print("the two processes as `ps` sees them (identical command lines, different cwd):")
for p, c in mine:
    where = "INSIDE the target" if p == inside.pid else "ANOTHER tree"
    print(f"  pid {p} [{where}] cwd={live.proc_cwd(p)}")
    print(f"      {c}")

print("\nBEFORE — the lane's base matcher (.archive/lane_base/), the same two pids:")
for e in base.collect_runner_executions({}, mine, None, TARGET.resolve()):
    where = "INSIDE" if e["pid"] == inside.pid else "ANOTHER TREE"
    print(f"  listed: pid {e['pid']} [{where}] {e['runner']} -> {e['test_path']} [{e['proof']}]")

print("\nAFTER — the matcher under proof (I-53), the same two pids:")
for e in live.collect_runner_executions({}, mine, None, TARGET.resolve()):
    where = "INSIDE" if e["pid"] == inside.pid else "ANOTHER TREE"
    print(f"  listed: pid {e['pid']} [{where}] {e['runner']} -> {e['test_path']} [{e['proof']}]")

print("\nLIVE — what the running circuit daemon published this frame:")
cs = ROOT / "system_scripts" / "circuit_state.json"
for _ in range(14):
    try:
        st = json.loads(cs.read_text())
    except Exception:
        st = {}
    entries = (((st.get("test_runners") or {}).get("execution") or {}).get("entries")) or []
    if any(e.get("pid") in (inside.pid, outside.pid) for e in entries):
        break
    time.sleep(5)
print(f"  frame {st.get('frame')} at {st.get('timestamp')}")
for e in entries:
    tag = ("OUR pytest, inside the target" if e.get("pid") == inside.pid else
           "THE FOREIGN pytest" if e.get("pid") == outside.pid else "another entry")
    print(f"  pid {e.get('pid')} {e.get('runner')} -> {e.get('test_path')} [{e.get('proof')}]  <- {tag}")
print(f"  inside pid {inside.pid} listed : {any(e.get('pid') == inside.pid for e in entries)}")
print(f"  foreign pid {outside.pid} listed: {any(e.get('pid') == outside.pid for e in entries)}")

for p in (inside, outside):
    p.kill()
    p.wait()
print("\nboth pytests killed")
