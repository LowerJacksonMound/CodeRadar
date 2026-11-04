"""teardown_identity.py — RUN_AGAINST_RULES rule 8: teardown verification is BYTE-IDENTITY against the
COPY-FIRST snapshot; mirror-sweep cleanliness alone is insufficient.

Q-H1-6 (2026-10-01, lane B2): until now only MCP `cr_stop` compared the target to its snapshot; the owner's
own close path (launch.sh / the overlay's close / Ctrl-C → the gearbox teardown) stamped `teardown_verified`
from the residue sweep alone. This module is the ONE comparison, shared by the gearbox teardown (every
launch, whoever started it), `cr_stop` and `run_proof.sh down`:

  * both sides are `snapshot_files.sh`'s ONE file set (env dirs / node_modules / tool caches / the root
    `.coderadar/` skipped on both sides), hashed with md5 — the same listing `cr_stop` writes;
  * the kept state mirrors are exempt through THE location helper (`scan_scope.is_mirror_path`), nothing
    else (owner ruling 2026-09-28);
  * the client's own edits — Q3: the CLIENT edits the target — are the only differences accounted for:
    `expected` names them (cr_stop's `expected_changes`, or the apply-lease + confirmed-ledger derivation
    `expected_from_ledgers` for a launch nobody passed a manifest to). EVERY differing path is named, in
    `client_edits` or in `changed`; nothing is hidden behind the verdict;
  * no snapshot for THIS run → NOT MEASURED with the reason, never "verified" (owner rule).
"""
from __future__ import annotations

import hashlib
import json
import pwd
import re
import subprocess
from pathlib import Path
from typing import Iterable, cast

SCRIPT_DIR = Path(__file__).resolve().parent
SNAPSHOT_FILES = SCRIPT_DIR / "snapshot_files.sh"


def _scan_scope():
    try:
        import scan_scope
    except ImportError:
        import sys
        sys.path.insert(0, str(SCRIPT_DIR))
        import scan_scope
    return scan_scope


def snapshot_roots(target: Path) -> list[Path]:
    """Where launch.sh puts the COPY-FIRST snapshot: `~/CodeRadar_snapshots` of the INVOKING owner (Item 7:
    under `sudo ./launch.sh` that is SUDO_USER's home, never root's). The target's owner is that person,
    so their home comes first; this process's own home second. Both are searched, duplicates dropped."""
    homes: list[Path] = []
    try:
        homes.append(Path(pwd.getpwuid(target.stat().st_uid).pw_dir))
    except (OSError, KeyError):
        pass
    homes.append(Path.home())
    return [h / "CodeRadar_snapshots" for h in dict.fromkeys(homes)]


def find_snapshot(name: str, roots: Iterable[Path], not_before: str | None = None) -> Path | None:
    """The newest `<name>_YYYYmmdd_HHMMSS` under *roots* — that exact form only (a bare `<name>_*` also
    matched another target whose name extends this one, run 178). With *not_before* (the same stamp form,
    the gearbox's own start stamp) only a snapshot taken AT OR AFTER it counts: a snapshot left by an
    earlier launch of the same target is never this run's reference."""
    exact = re.compile(re.escape(name) + r"_(\d{8}_\d{6})")
    stamped = {p: exact.fullmatch(p.name) for base in roots if base.is_dir() for p in base.iterdir() if p.is_dir()}
    found = [(m.group(1), p) for p, m in stamped.items() if m and m.group(1) >= (not_before or "")]
    return max(found)[1] if found else None


def md5_listing(root: Path) -> dict[str, str]:
    """{root-relative posix path: md5} over `snapshot_files.sh`'s ONE file set under *root*. A file that
    cannot be read hashes to `unreadable:<error>` so it is a difference, never a silent skip."""
    listing = subprocess.run(["bash", str(SNAPSHOT_FILES), "."], cwd=str(root),
                             capture_output=True, text=True)
    if listing.returncode != 0:
        raise RuntimeError(f"snapshot_files.sh failed under {root}: rc={listing.returncode} "
                           f"{listing.stderr.strip()[:200]}")
    out: dict[str, str] = {}
    for rel in (line.strip().removeprefix("./") for line in listing.stdout.splitlines() if line.strip()):
        h = hashlib.md5(usedforsecurity=False)   # a checksum, the same one `md5 -r` prints
        try:
            with open(root / rel, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            out[rel] = h.hexdigest()
        except OSError as e:
            out[rel] = f"unreadable:{type(e).__name__}"
    return out


def as_text(side: dict[str, str]) -> str:
    """The `md5 -r` form cr_stop and run_proof.sh write to `teardown_*.md5`: `<hash> ./<path>` per line."""
    return "".join(f"{h} ./{p}\n" for p, h in sorted(side.items()))


def compare(target: Path, snapshot: Path | None, expected: Iterable[str] = ()) -> dict:
    """The comparison. Returns a dict whose `status` is MEASURED or NOT MEASURED:
       verified      True (no unexpected difference) / False (`changed` names each one) / None (NOT MEASURED)
       changed       differing paths NOT in *expected* — CodeRadar, or someone, touched them
       client_edits  differing paths *expected* names — the client's own edits
       files_compared, snapshot, reason, sides (the two md5 texts, for the run's record files)."""
    out: dict = {"status": "NOT MEASURED", "reason": None, "snapshot": None if snapshot is None else str(snapshot),
                 "files_compared": 0, "changed": [], "client_edits": [], "verified": None, "sides": ("", "")}
    # The one NOT MEASURED gate, with its reason: a comparison that cannot run is said, never "verified".
    out["reason"] = (
        "no COPY-FIRST snapshot for this run — nothing to compare the target against" if snapshot is None
        else f"snapshot is not a directory: {snapshot}" if not snapshot.is_dir()
        else f"{SNAPSHOT_FILES.name} missing — the file set cannot be listed" if not SNAPSHOT_FILES.is_file()
        else None)
    if out["reason"]:
        return out
    reference = cast(Path, snapshot)   # the gate above returned on None
    try:
        snap_side, tgt_side = md5_listing(reference), md5_listing(Path(target))
    except (OSError, RuntimeError) as e:
        out["reason"] = f"comparison aborted: {type(e).__name__}: {e}"
        return out
    is_mirror = _scan_scope().is_mirror_path
    named = {str(p).strip().removeprefix("./") for p in expected if str(p).strip()}
    moved = sorted(p for p in set(snap_side) | set(tgt_side)
                   if snap_side.get(p) != tgt_side.get(p) and not is_mirror(p))
    out.update({
        "status": "MEASURED", "files_compared": len(snap_side), "sides": (as_text(snap_side), as_text(tgt_side)),
        "client_edits": [p for p in moved if p in named],
        "changed": [p for p in moved if p not in named],
    })
    out["verified"] = not out["changed"]
    return out


def expected_from_ledgers(repo_id: str, script_dir: Path | None = None) -> set[str]:
    """Q-H4-4's server-side manifest for a run nobody passed `expected_changes` to: every target-relative
    `file` the apply lease handed a diff for (`apply_lease_<repo_id>.jsonl`, the identity cr_apply hands
    out) plus every file the confirmed ledger records an outcome for (`confirmed_ledger_<repo_id>.jsonl`;
    `file`, else the `row_key`'s `<file>::…` head). A missing or unreadable ledger contributes nothing."""
    base = script_dir or SCRIPT_DIR
    files: set[str] = set()
    for stem in ("apply_lease_", "confirmed_ledger_"):
        path = base / f"{stem}{repo_id}.jsonl"
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                doc = json.loads(line.strip() or "null")
            except ValueError:
                doc = None
            doc = doc if isinstance(doc, dict) else {}   # a line that is not the contract names no file
            rel = str(doc.get("file") or "") or str(doc.get("row_key") or "").split("::", 1)[0]
            if rel:
                files.add(rel.removeprefix("./"))
    return files


def write_records(run_dir: Path, result: dict) -> None:
    """The run's record files, the names `cr_stop` and `run_proof.sh down` already use, plus the verdict.
    Writes nothing but the verdict when the comparison was NOT MEASURED. Never raises."""
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        if result["status"] == "MEASURED":
            snap_txt, tgt_txt = result["sides"]
            (run_dir / "teardown_snapshot.md5").write_text(snap_txt, encoding="utf-8")
            (run_dir / "teardown_target.md5").write_text(tgt_txt, encoding="utf-8")
            diff = subprocess.run(["diff", str(run_dir / "teardown_snapshot.md5"),
                                   str(run_dir / "teardown_target.md5")], capture_output=True, text=True)
            (run_dir / "teardown_diff.txt").write_text(diff.stdout, encoding="utf-8")
        record = {k: v for k, v in result.items() if k != "sides"}
        (run_dir / "teardown_identity.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    except OSError:
        pass


def verdict_lines(result: dict) -> list[str]:
    """What the owner reads at close: one TEARDOWN IDENTITY line, then every differing path by name."""
    snap = result.get("snapshot") or "?"
    if result["status"] != "MEASURED":
        return [f"TEARDOWN IDENTITY: NOT MEASURED — {result.get('reason')}"]
    edits = result["client_edits"]
    lines = []
    if result["verified"]:
        lines.append(f"TEARDOWN IDENTITY: verified — {result['files_compared']} files byte-identical to "
                     f"snapshot {snap}" + (f" apart from {len(edits)} client edit(s)" if edits else ""))
    else:
        lines.append(f"TEARDOWN IDENTITY: NOT verified — {len(result['changed'])} file(s) differ from "
                     f"snapshot {snap} beyond the client's edits")
        lines.extend(f"changed: {p}" for p in result["changed"])
    lines.extend(f"client edit (leased or confirmed): {p}" for p in edits)
    return lines
