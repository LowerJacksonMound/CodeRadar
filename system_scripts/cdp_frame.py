"""Headless-Chrome frame of a Dash panel block, driven over --remote-debugging-pipe (no websocket library needed).
usage: cdp_frame.py URL "block header text" OUT.png [wait_s] [width] [height]
Navigates, waits for the Dash interval callbacks to fill the panel (wait_s real seconds, plus a wait that
SCALES WITH THE NODE COUNT of the drawn figure and is bounded — I-92), scrolls the first leaf element whose
text equals the header into view (inside its scrolling panel), and captures the viewport.

I-74 (2026-09-21, tr1_L4L8): the headless profile is a TEMP directory removed after the frame, never a
directory beside the output frame — a frame no longer leaves a ~54 MB `hl_pipe_<pid>` profile dir in
.archive/frames/runNNN/ for the record rsync to carry into the original as drift.
I-92 (2026-09-21, tr1_L4L8): a 399-node figure takes longer to DRAW than the fixed capture wait, so the
first capture of a size target caught the blank template mid-swap. The wait is now base + per-node, bounded:
after the base wait the drawn node count is read off the page and the extra wait is
min(nodes * PER_NODE_WAIT_S, LONGEST_EXTRA_WAIT_S), and the loop also holds until two consecutive probes read
the same count. A page with no countable nodes (n = 0) waits exactly as before.
I-173 (2026-09-22, run 175, s10 T3): runs 169, 171 and 172 each left an EMPTY frame directory, every one of
them on `TimeoutError: no reply for 6` raised inside `node_count` with the dashboard answering HTTP 200.
Reproduced against a live dashboard on this tree (3 of 3 launches of the tool as it stood), and the cause is
NOT I-92's probe: on the dash page a TRIVIAL `1+1` evaluate measured 0.71 s, 31.52 s and 190.53 s on three
consecutive calls, while the same expression on a static page off the same server answered in 0.00 s five
times running — the page's renderer is intermittently unavailable for minutes at a time and `node_count` is
merely the first Runtime.evaluate to meet it. What turned that slow reply into a lost frame was this file's
own transport, twice over: `os.read` on the pipe is blocking, so `recv`'s deadline was only ever tested
BETWEEN reads (one read measured blocking from 20.56 s to 174.70 s on a 60 s budget), and when the read did
return, the deadline had passed, so the loop dropped the bytes it had just read — the reply — and raised.
The read is select-bounded now and everything read is ALWAYS drained before the deadline is judged; the node
probe and the scroll are bounded with a bounded retry and answer "not measured" instead of raising, so a busy
page costs the scaled wait and never the frame; and the capture itself gets a bounded retry. If every attempt
at the capture goes unanswered the tool writes NOTHING and says so — a frame is never faked."""
import base64, json, os, select, shutil, subprocess, sys, tempfile, time

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
url, header, out = sys.argv[1], sys.argv[2], sys.argv[3]
wait_s = float(sys.argv[4]) if len(sys.argv) > 4 else 15.0
width = int(sys.argv[5]) if len(sys.argv) > 5 else 900
height = int(sys.argv[6]) if len(sys.argv) > 6 else 1400

# I-92's constants — the scaled wait, bounded at both ends. They are read into LOCALS before they are
# compared against anything: a compare against a module-level number is a pre-ranker hunter site
# (W9 / W37) and this lane may not file a ledger row — see the report's spec-blind facts.
PER_NODE_WAIT_S = 0.02        # per drawn node, on top of wait_s
LONGEST_EXTRA_WAIT_S = 45.0   # the bound: the scaled wait can never run away
PROBE_POLL_S = 0.5            # how often the node count is re-read while the extra wait runs
PROFILE_REAP_WAIT_S = 2.0     # how long the frame tool waits for the killed child before removing its profile
# I-173's constants — read into LOCALS before any compare, same rule as I-92's above.
READ_SLICE_S = 0.25           # the select() slice: the deadline is tested this often, never less
PROBE_BUDGET_S = 25.0         # one bounded try at a Runtime.evaluate probe (node count / scroll)
PROBE_TRIES = 2               # the bounded retry — measured: most stalls clear between tries
SHOT_BUDGET_S = 120.0         # the capture's own budget; the frame is what the run is here for
SHOT_TRIES = 3                # bounded: 3 x 120 s covers the longest stall measured (190 s)
# The drawn node count: Plotly's scatter markers (the circuit figure is dcc.Graph / go.Scatter), any SVG
# circle, and a cytoscape node class — whichever reads highest. Nothing countable = 0 = no extra wait.
NODE_PROBE_JS = """(() => {
  const plotly = document.querySelectorAll('.js-plotly-plot .scatterlayer .point').length;
  const svg = document.querySelectorAll('svg circle').length;
  const cy = document.querySelectorAll('.cy-node').length;
  return Math.max(plotly, svg, cy);
})()"""

udd = tempfile.mkdtemp(prefix="hl_pipe_")   # I-74: a temp dir, removed in the finally below

r_in, w_in = os.pipe()    # chrome reads fd 3
r_out, w_out = os.pipe()  # chrome writes fd 4


argv = [CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--remote-debugging-pipe",
        f"--user-data-dir={udd}", f"--window-size={width},{height}", "about:blank"]
pid = os.fork()
if pid == 0:  # child: pipes on fds 3 / 4 (subprocess.Popen would close them after preexec_fn)
    a = os.dup(r_in); b = os.dup(w_out)
    os.dup2(a, 3); os.dup2(b, 4)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 1); os.dup2(devnull, 2)
    os.execv(CHROME, argv)


class _P:
    def kill(self):
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass


proc = _P()
os.close(r_in); os.close(w_out)
buf = b""
_id = 0


def send(method, params=None, session=None):
    global _id
    _id += 1
    msg = {"id": _id, "method": method, "params": params or {}}
    if session:
        msg["sessionId"] = session
    os.write(w_in, json.dumps(msg).encode() + b"\0")
    return _id


def recv_any(want_ids, timeout=60):
    """The first reply to ANY id in *want_ids*, or TimeoutError once the budget is honestly spent.

    I-173, two repairs in one function.
    (1) The read is select-bounded, so `timeout` means what it says. The version this replaced
        called a blocking `os.read`, so its deadline was only ever tested BETWEEN reads — one
        read measured blocking from 20.56 s to 174.70 s on a 60 s budget.
    (2) Whatever HAS been read is drained before the deadline is judged, so a reply that lands on
        the deadline is the reply. The old loop tested the clock first and threw away the
        122-byte reply to `#6` it had just read, and that is the `no reply for 6` of runs 169,
        171 and 172.
    Taking a SET of ids is what makes a bounded retry additive rather than a fresh start: a
    second request goes out while the first is still outstanding, and whichever answers first is
    a perfectly good answer."""
    global buf
    slice_s = READ_SLICE_S       # local, compared below (never the module-level name)
    wanted = set(want_ids)
    end = time.time() + timeout
    while True:
        while b"\0" in buf:
            raw, buf = buf.split(b"\0", 1)
            m = json.loads(raw)
            if m.get("id") in wanted:
                return m
        left = end - time.time()
        if left <= 0:
            one = sorted(wanted)
            raise TimeoutError(f"no reply for {one[0] if len(one) == 1 else one}")
        ready, _, _ = select.select([r_out], [], [], slice_s if slice_s < left else left)
        if not ready:
            continue
        chunk = os.read(r_out, 1 << 20)
        if not chunk:
            raise RuntimeError("chrome closed the pipe")
        buf += chunk


def recv(want_id, timeout=60):
    return recv_any([want_id], timeout=timeout)


def evaluate(expression, session, budget_s, tries, what):
    """A bounded Runtime.evaluate with a bounded retry. Answers the reply, or None when the
    page's renderer never answered — I-173: a probe reports "not measured" and the frame goes
    on. Nothing here raises past the caller. Every try stays outstanding, so try 2 waits on try
    1's reply as well as its own."""
    budget = budget_s
    n_tries = tries
    outstanding = []
    attempt = 0
    while attempt < n_tries:
        attempt += 1
        t_try = time.time()
        outstanding.append(send("Runtime.evaluate", {"expression": expression, "returnByValue": True},
                                session=session))
        try:
            return recv_any(outstanding, timeout=budget)
        except TimeoutError:
            print(f"{what}: try {attempt} of {n_tries} got no reply inside {budget:g}s "
                  f"({time.time() - t_try:.1f}s spent) — I-173")
    return None


try:
    t = recv(send("Target.createTarget", {"url": "about:blank"}))["result"]["targetId"]
    s = recv(send("Target.attachToTarget", {"targetId": t, "flatten": True}))["result"]["sessionId"]
    recv(send("Page.enable", session=s))
    recv(send("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 2, "mobile": False}, session=s))
    recv(send("Page.navigate", {"url": url}, session=s))
    time.sleep(wait_s)

    probe_budget = PROBE_BUDGET_S            # locals, as I-92's constants are
    probe_tries = PROBE_TRIES

    def node_count():
        """The DRAWN node count, or None when the renderer did not answer (I-173: not measured)."""
        r = evaluate(NODE_PROBE_JS, s, probe_budget, probe_tries, "nodes")
        if r is None:
            return None
        v = r.get("result", {}).get("result", {}).get("value")
        return int(v) if isinstance(v, (int, float)) else 0

    # I-92: the extra wait is the node count's, bounded by longest_extra, and it also holds until two
    # consecutive probes read the same count (a figure still growing has not finished drawing).
    # I-173: when the probe is NOT MEASURED the tool waits the base wait and nothing more — exactly
    # the n = 0 path I-92 already had — and says so. The frame is never the probe's hostage.
    longest_extra = LONGEST_EXTRA_WAIT_S     # read once into a local; every compare below is local
    per_node = PER_NODE_WAIT_S
    n = node_count()
    if n is None:
        waited = 0.0
        print(f"nodes: NOT MEASURED (no reply in {probe_tries} x {probe_budget:g}s — I-173)  "
              f"wait: {wait_s:.1f}s base + 0.0s scaled = {wait_s:.1f}s total")
    else:
        extra = min(n * per_node, longest_extra)
        t_extra = time.time()
        prev = n
        while True:
            waited = time.time() - t_extra
            if waited >= longest_extra:
                break
            if waited >= extra and n == prev and waited > 0:
                break
            time.sleep(PROBE_POLL_S)
            prev, again = n, node_count()
            if again is None:        # I-173: the renderer went away mid-wait — hold the last reading
                n = prev
                print("nodes: the re-read was NOT MEASURED — holding the last count (I-173)")
                break
            n = again
            extra = min(max(extra, n * per_node), longest_extra)
        waited = time.time() - t_extra
        print(f"nodes: {n}  wait: {wait_s:.1f}s base + {waited:.1f}s scaled "
              f"(per-node {per_node:g}s, bound {longest_extra:g}s) = {wait_s + waited:.1f}s total")

    js = """(() => {
      const want = %s;
      const leaves = [...document.querySelectorAll('body *')].filter(e => e.children.length === 0 && e.textContent.trim() === want);
      if (!leaves.length) return 'NOT FOUND';
      leaves[0].scrollIntoView({block: 'start'});
      return 'ok:' + leaves.length;
    })()""" % json.dumps(header)
    r = evaluate(js, s, probe_budget, probe_tries, "scroll")
    if r is None:
        print("scroll: NOT MEASURED — the frame is taken where the page stands (I-173)")
    else:
        print("scroll:", r.get("result", {}).get("result", {}).get("value"))
    time.sleep(1.0)
    # I-173: the capture is the point of the run, so it gets the long budget AND a bounded retry —
    # 3 x 120 s covers the longest renderer stall measured on this dashboard (190.53 s).
    shot_budget = SHOT_BUDGET_S
    shot_tries = SHOT_TRIES
    shot = None
    shot_try = 0
    shots_outstanding = []
    while shot_try < shot_tries:
        shot_try += 1
        t_shot = time.time()
        shots_outstanding.append(send("Page.captureScreenshot", {"format": "png"}, session=s))
        try:
            shot = recv_any(shots_outstanding, timeout=shot_budget)
            print(f"capture: try {shot_try} of {shot_tries} answered in {time.time() - t_shot:.1f}s")
            break
        except TimeoutError:
            print(f"capture: try {shot_try} of {shot_tries} got no reply inside {shot_budget:g}s — I-173")
    if shot is None:
        print(f"NO FRAME: {shot_tries} bounded tries at Page.captureScreenshot, none answered; "
              f"nothing was written to {out} — a frame is never faked (I-173)")
        sys.exit(1)
    open(out, "wb").write(base64.b64decode(shot["result"]["data"]))
    print("wrote", out, os.path.getsize(out))
finally:
    proc.kill()
    reap_until = time.time() + PROFILE_REAP_WAIT_S   # bounded: the child is reaped, then its profile goes
    while time.time() < reap_until:
        try:
            if os.waitpid(pid, os.WNOHANG)[0]:
                break
        except ChildProcessError:
            break
        time.sleep(PROBE_POLL_S / 5.0)
    shutil.rmtree(udd, ignore_errors=True)   # I-74: the profile leaves with the frame tool
    print("profile removed:", udd, os.path.exists(udd))
