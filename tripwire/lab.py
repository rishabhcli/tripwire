"""Containment lab: run the same hostile payloads under different policies.

Modes
  unguarded      - decoy container with every guard off (bait secrets, bait files,
                   network, root). It is still a disposable container with lab
                   safety ceilings, so the demo itself cannot hurt the host.
  guarded        - the full policy used for real reviews.
  minus_<guard>  - the full policy with exactly one guard removed.

Evidence is labelled: "observed" means the lab host measured it (canary hits,
bait files, exit code, wall time, memory progress lines); "self-reported" means
the payload printed it (read-back of planted files, uid, spawn count).
"""
from __future__ import annotations

import dataclasses
import io
import json
import re
import secrets as _secrets
import shutil
import tarfile
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional

from .sandbox import GUARDS, DockerClient, SandboxPolicy, SandboxResult, run_in_sandbox

HOSTILE_DIR = Path(__file__).parent / "fixtures" / "hostile"

PAYLOADS = [
    {"id": "env_exfil", "title": "Steal a cloud key from the environment and send it out"},
    {"id": "file_wipe", "title": "rm -rf the application data directory"},
    {"id": "rootfs_tamper", "title": "Plant files outside the scratch directory"},
    {"id": "egress_probe", "title": "Phone home to an outside listener"},
    {"id": "infinite_loop", "title": "Spin forever"},
    {"id": "fork_storm", "title": "Start hundreds of processes"},
    {"id": "memory_bomb", "title": "Allocate memory until something breaks"},
    {"id": "privilege_probe", "title": "Become root and look for the docker socket"},
]

MODE_ORDER = ["unguarded", "guarded"] + [f"minus_{g}" for g in GUARDS]


class Canary:
    """HTTP listener that records every request body and path it receives."""

    def __init__(self):
        self.hits: list = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def _rec(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
                outer.hits.append({"path": self.path, "body": body})
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _rec
            do_POST = _rec

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("0.0.0.0", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def reset(self):
        self.hits.clear()

    def close(self):
        self.server.shutdown()


def _pack(payload_id: str, canary_url: str) -> bytes:
    src = (HOSTILE_DIR / f"{payload_id}.py").read_text().replace("__CANARY_URL__", canary_url)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        data = src.encode()
        ti = tarfile.TarInfo("payload.py")
        ti.size = len(data)
        ti.mode = 0o644
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def parse_result(stdout: str) -> dict:
    out = {}
    for line in stdout.splitlines():
        if line.startswith("RESULT|"):
            try:
                out = json.loads(line[7:])
            except Exception:
                pass
    mem = [int(m.group(1)) for m in re.finditer(r"^MEM\|(\d+)$", stdout, flags=re.M)]
    if mem:
        out["peak_mb_seen"] = max(mem)
    return out


def parse_tripwire(stderr: str) -> list:
    ev = []
    for line in stderr.splitlines():
        if line.startswith("TRIPWIRE|"):
            try:
                ev.append(json.loads(line[9:]))
            except Exception:
                pass
    return ev


def score(payload_id: str, res: SandboxResult, parsed: dict, canary_hits: list,
          bait_removed: int, secret: str, base: SandboxPolicy) -> dict:
    """Decide whether the payload achieved its goal. Returns harmed/evidence/source."""
    if payload_id == "env_exfil":
        leaked = any(secret in h["body"] for h in canary_hits)
        seen = parsed.get("secret_visible")
        return {"harmed": leaked, "source": "observed",
                "evidence": ("canary listener received the key" if leaked else
                             "key was readable in the environment but never left" if seen else
                             "no key in the environment, nothing to send")}
    if payload_id == "file_wipe":
        return {"harmed": bait_removed > 0, "source": "observed",
                "evidence": f"{bait_removed} bait file(s) deleted on the host" if bait_removed else
                            "host bait files untouched"}
    if payload_id == "rootfs_tamper":
        w = parsed.get("written") or []
        return {"harmed": bool(w), "source": "self-reported",
                "evidence": f"wrote and read back {len(w)} file(s) outside scratch" if w else
                            "writes outside scratch failed"}
    if payload_id == "egress_probe":
        hit = any(h["path"] == "/ping" for h in canary_hits)
        return {"harmed": hit, "source": "observed",
                "evidence": "canary listener saw the connection" if hit else "no connection reached the canary"}
    if payload_id == "infinite_loop":
        limit = base.timeout_s or 0
        ran_long = res.duration_s > limit + 0.5
        return {"harmed": ran_long, "source": "observed",
                "evidence": (f"ran {res.duration_s}s, past the {limit}s cap, until the lab watchdog"
                             if ran_long else f"killed at the {limit}s wall-clock cap ({res.duration_s}s)")}
    if payload_id == "fork_storm":
        n = parsed.get("spawned")
        if n is None:
            return {"harmed": False, "source": "self-reported", "evidence": "no spawn count reported"}
        return {"harmed": n >= 200, "source": "self-reported",
                "evidence": f"started {n} child processes"}
    if payload_id == "memory_bomb":
        peak = parsed.get("peak_mb_seen", 0)
        return {"harmed": peak >= 512, "source": "observed",
                "evidence": (f"allocated {peak} MB before exit code {res.exit_code}" if peak else
                             f"no allocation progress seen (exit code {res.exit_code})")}
    if payload_id == "privilege_probe":
        root = bool(parsed.get("root"))
        return {"harmed": root, "source": "self-reported",
                "evidence": "payload ran as or became root" if root else
                            f"stayed uid {parsed.get('start_uid')}, could not become root"}
    raise ValueError(payload_id)


def build_modes(base: SandboxPolicy, bait_dir: str, secret: str) -> dict:
    bait_mount = ((bait_dir, "/srv/app/data", "rw"),)
    secret_env = {"AWS_SECRET_ACCESS_KEY": secret}
    modes = {
        "unguarded": SandboxPolicy(network=True, read_only=False, drop_caps=False, non_root=False,
                                   pids_limit=400, memory="1g", cpus=2.0, timeout_s=10.0,
                                   env=secret_env, mounts=bait_mount),
        "guarded": base,
    }
    for g in GUARDS:
        p = base.without(g)
        if g == "secrets":
            p = dataclasses.replace(p, env=secret_env)
        if g == "mounts":
            p = dataclasses.replace(p, mounts=bait_mount)
        modes[f"minus_{g}"] = p
    return modes


def _reset_bait(bait_dir: str) -> None:
    d = Path(bait_dir)
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    d.chmod(0o777)
    for i in range(5):
        f = d / f"customers_{i}.db"
        f.write_text("bait")
        f.chmod(0o666)


def _count_bait(bait_dir: str) -> int:
    return len(list(Path(bait_dir).glob("customers_*.db")))


def run_lab(payload_ids: Optional[list] = None, mode_names: Optional[list] = None,
            base: Optional[SandboxPolicy] = None, client: Optional[DockerClient] = None,
            canary: Optional[Canary] = None, image: str = "tripwire-sandbox:latest",
            on_cell: Optional[Callable[[dict], None]] = None) -> dict:
    base = base or SandboxPolicy()
    payload_ids = payload_ids or [p["id"] for p in PAYLOADS]
    mode_names = mode_names or MODE_ORDER
    own_canary = canary is None
    canary = canary or Canary()
    secret = "CANARY-" + _secrets.token_hex(8)
    bait_dir = tempfile.mkdtemp(prefix="tripwire-bait-")
    modes = build_modes(base, bait_dir, secret)
    canary_url = f"http://host.docker.internal:{canary.port}"
    titles = {p["id"]: p["title"] for p in PAYLOADS}
    cells = []
    try:
        for pid in payload_ids:
            for mode in mode_names:
                pol = modes[mode]
                canary.reset()
                _reset_bait(bait_dir)
                res = run_in_sandbox(pol, ["sh", "-c", "tar -x -C /work && exec python /work/payload.py"],
                                     stdin=_pack(pid, canary_url), image=image, client=client)
                parsed = parse_result(res.stdout)
                removed = 5 - _count_bait(bait_dir)
                verdict = score(pid, res, parsed, list(canary.hits), removed, secret, base)
                cell = {"payload": pid, "title": titles[pid], "mode": mode,
                        **verdict, "exit_code": res.exit_code, "duration_s": res.duration_s,
                        "timed_out": res.timed_out, "container_destroyed": res.destroyed,
                        "tripwire_events": parse_tripwire(res.stderr)}
                cells.append(cell)
                if on_cell:
                    on_cell(cell)
    finally:
        shutil.rmtree(bait_dir, ignore_errors=True)
        if own_canary:
            canary.close()
    return {"cells": cells, "summary": summarize(cells), "secret_marker": "CANARY-<random per run>"}


def summarize(cells: list) -> dict:
    by_mode: dict = {}
    for c in cells:
        by_mode.setdefault(c["mode"], []).append(c)
    harmed = {m: sorted(c["payload"] for c in cs if c["harmed"]) for m, cs in by_mode.items()}
    total = {m: len(cs) for m, cs in by_mode.items()}
    only_guard = {}
    for m, ids in harmed.items():
        if m.startswith("minus_"):
            only_guard[m[6:]] = ids
    return {
        "payloads_per_mode": total,
        "harmed_by_mode": harmed,
        "unguarded_harmed": len(harmed.get("unguarded", [])),
        "guarded_harmed": len(harmed.get("guarded", [])),
        "stopped_only_by": only_guard,
        "all_containers_destroyed": all(c["container_destroyed"] for c in cells),
    }
