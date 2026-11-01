"""Sandbox policy and Docker runner.

The boundary is the container, never the app process. Every guard below maps to
one `docker run` flag, so the policy can be inspected and each guard can be
removed one at a time by the containment lab (see lab.py) to measure what it
actually stops.
"""
from __future__ import annotations

import dataclasses
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

DEFAULT_IMAGE = "tripwire-sandbox:latest"

# Names of the individually removable guards.
GUARDS = ("network", "read_only", "caps", "user", "pids", "memory", "timeout", "secrets", "mounts")


@dataclass(frozen=True)
class SandboxPolicy:
    network: bool = False            # False -> --network none
    read_only: bool = True           # read-only root filesystem
    drop_caps: bool = True           # --cap-drop ALL + no-new-privileges
    non_root: bool = True            # run as uid 65534
    pids_limit: Optional[int] = 64
    memory: Optional[str] = "128m"
    cpus: Optional[float] = 0.5
    timeout_s: Optional[float] = 8.0
    tmpfs_size: str = "32m"
    env: dict = field(default_factory=dict)       # explicit env only; nothing is inherited
    mounts: tuple = ()                            # (host_path, container_path, mode)
    runtime: Optional[str] = None                 # e.g. "runsc" for gVisor
    # Lab safety ceilings: applied when a guard is removed so a removed limit
    # cannot take down the demo host. Reported in every receipt.
    watchdog_s: float = 12.0

    def without(self, guard: str, ceilings: Optional[dict] = None) -> "SandboxPolicy":
        """Return a copy with one guard removed (limits relax to lab ceilings)."""
        if guard not in GUARDS:
            raise ValueError(f"unknown guard {guard!r}")
        c = {"pids": 400, "memory": "1g", "timeout": 10.0, **(ceilings or {})}
        if guard == "network":
            return dataclasses.replace(self, network=True)
        if guard == "read_only":
            return dataclasses.replace(self, read_only=False)
        if guard == "caps":
            return dataclasses.replace(self, drop_caps=False)
        if guard == "user":
            return dataclasses.replace(self, non_root=False)
        if guard == "pids":
            return dataclasses.replace(self, pids_limit=c["pids"])
        if guard == "memory":
            return dataclasses.replace(self, memory=c["memory"])
        if guard == "timeout":
            return dataclasses.replace(self, timeout_s=c["timeout"])
        if guard in ("secrets", "mounts"):
            return self  # what the caller injects or mounts; the lab applies these, see lab.py
        raise AssertionError(guard)

    def receipt(self) -> dict:
        """Human-readable summary of the guards that were active for a run."""
        return {
            "network": "enabled" if self.network else "none",
            "root_filesystem": "writable" if not self.read_only else "read-only",
            "capabilities": "default" if not self.drop_caps else "all dropped, no-new-privileges",
            "user": "root" if not self.non_root else "uid 65534",
            "pids_limit": self.pids_limit,
            "memory_limit": self.memory,
            "cpus": self.cpus,
            "timeout_s": self.timeout_s,
            "env_vars_injected": sorted(self.env.keys()),
            "host_mounts": [m[1] for m in self.mounts],
            "runtime": self.runtime or "runc (default)",
        }


@dataclass
class SandboxResult:
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool
    container: str
    destroyed: bool
    policy: dict

    @property
    def oom_killed(self) -> bool:
        return self.exit_code == 137 and not self.timed_out


def docker_args(policy: SandboxPolicy, image: str, name: str, cmd: list, interactive: bool = False) -> list:
    """Build the `docker run` argv for a policy. Pure function, unit tested."""
    a = ["docker", "run", "--rm", "--name", name]
    if interactive:
        a.append("-i")
    if policy.runtime:
        a += ["--runtime", policy.runtime]
    if not policy.network:
        a += ["--network", "none"]
    else:
        a += ["--add-host", "host.docker.internal:host-gateway"]
    if policy.read_only:
        a.append("--read-only")
    if policy.drop_caps:
        a += ["--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    if policy.non_root:
        a += ["--user", "65534:65534"]
    if policy.pids_limit is not None:
        a += ["--pids-limit", str(policy.pids_limit)]
    if policy.memory is not None:
        a += ["--memory", policy.memory, "--memory-swap", policy.memory]
    if policy.cpus is not None:
        a += ["--cpus", str(policy.cpus)]
    # Writable scratch space that never touches the host.
    a += ["--tmpfs", f"/work:rw,size={policy.tmpfs_size},mode=1777",
          "--tmpfs", f"/tmp:rw,size={policy.tmpfs_size},mode=1777"]
    for host, ctr, mode in policy.mounts:
        a += ["-v", f"{host}:{ctr}:{mode}"]
    for k, v in policy.env.items():
        a += ["-e", f"{k}={v}"]
    a += ["--workdir", "/work", image] + list(cmd)
    return a


class DockerClient:
    """Thin wrapper over the docker CLI so tests can inject a fake."""

    def __init__(self, binary: str = "docker"):
        self.binary = binary

    def run(self, argv: list, stdin: Optional[bytes], timeout: Optional[float]):
        argv = [self.binary] + argv[1:]
        return subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)

    def exists(self, name: str) -> bool:
        p = subprocess.run([self.binary, "ps", "-a", "-q", "--filter", f"name=^{name}$"],
                           capture_output=True)
        return bool(p.stdout.strip())

    def kill_and_remove(self, name: str) -> None:
        subprocess.run([self.binary, "rm", "-f", name], capture_output=True)


def run_in_sandbox(policy: SandboxPolicy, cmd: list, stdin: Optional[bytes] = None,
                   image: str = DEFAULT_IMAGE, client: Optional[DockerClient] = None) -> SandboxResult:
    """Run `cmd` in a fresh container, enforce the wall-clock cap, destroy it afterwards."""
    client = client or DockerClient()
    name = f"tripwire-{uuid.uuid4().hex[:12]}"
    argv = docker_args(policy, image, name, cmd, interactive=stdin is not None)
    cap = policy.timeout_s if policy.timeout_s is not None else policy.watchdog_s
    t0 = time.monotonic()
    timed_out = False
    try:
        p = client.run(argv, stdin, cap)
        code, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        code = None
        out, err = e.stdout or b"", e.stderr or b""
    finally:
        client.kill_and_remove(name)
    dur = time.monotonic() - t0
    return SandboxResult(
        exit_code=code,
        stdout=(out or b"").decode("utf-8", "replace"),
        stderr=(err or b"").decode("utf-8", "replace"),
        duration_s=round(dur, 3),
        timed_out=timed_out,
        container=name,
        destroyed=not client.exists(name),
        policy=policy.receipt(),
    )
