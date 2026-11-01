"""Tripwire audit hook, loaded inside the sandbox via PYTHONPATH.

This is OBSERVABILITY, not the security boundary. The boundary is the container
(see sandbox.py). Hostile code can try to remove an audit hook, so the report
treats these lines as "attempts we saw", never as proof that nothing happened.
"""
import json
import sys

_SENSITIVE = ("/.ssh", "/.aws", "/.env", "/etc/shadow", "/var/run/docker.sock", "/run/secrets")


def _emit(kind, detail):
    try:
        sys.stderr.write("TRIPWIRE|" + json.dumps({"kind": kind, "detail": str(detail)[:200]}) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def _hook(event, args):
    try:
        if event == "socket.connect":
            _emit("network_connect", args[1])
        elif event == "open":
            p = str(args[0])
            if any(s in p for s in _SENSITIVE) or (p.startswith("/proc/") and p.endswith("/environ")):
                _emit("sensitive_read", p)
        elif event in ("os.remove", "os.rmdir"):
            _emit("delete", args[0])
        elif event in ("subprocess.Popen", "os.system", "os.posix_spawn"):
            _emit("spawn", args[0] if event == "os.system" else args[:2])
    except Exception:
        pass


sys.addaudithook(_hook)
