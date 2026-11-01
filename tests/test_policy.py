import subprocess
from tripwire.sandbox import GUARDS, SandboxPolicy, docker_args, run_in_sandbox
from conftest import FakeDocker, FakeProc


def flags(p, **kw):
    return docker_args(p, "img", "n1", ["true"], **kw)


def test_default_policy_applies_every_guard():
    a = flags(SandboxPolicy())
    s = " ".join(a)
    assert "--network none" in s
    assert "--read-only" in a
    assert "--cap-drop ALL" in s and "no-new-privileges" in s
    assert "--user 65534:65534" in s
    assert "--pids-limit 64" in s
    assert "--memory 128m" in s and "--memory-swap 128m" in s
    assert "--cpus 0.5" in s
    assert "--rm" in a
    assert not any(x == "-e" for x in a), "no environment may be injected by default"
    assert not any(x == "-v" for x in a), "no host mounts by default"


def test_each_removed_guard_changes_exactly_its_flag():
    base = SandboxPolicy()
    assert "--network" not in flags(base.without("network"))
    assert "--read-only" not in flags(base.without("read_only"))
    assert "--cap-drop" not in flags(base.without("caps"))
    assert "--user" not in flags(base.without("user"))
    assert "--pids-limit 400" in " ".join(flags(base.without("pids")))
    assert "--memory 1g" in " ".join(flags(base.without("memory")))
    assert base.without("timeout").timeout_s == 10.0


def test_unknown_guard_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        SandboxPolicy().without("magic")


def test_all_guards_have_a_removal_path():
    for g in GUARDS:
        SandboxPolicy().without(g)


def test_receipt_reports_what_was_applied():
    r = SandboxPolicy().receipt()
    assert r["network"] == "none" and r["env_vars_injected"] == [] and r["host_mounts"] == []
    r2 = SandboxPolicy(env={"K": "v"}, mounts=(("/a", "/b", "rw"),)).receipt()
    assert r2["env_vars_injected"] == ["K"] and r2["host_mounts"] == ["/b"]


def test_container_is_always_removed_even_on_timeout():
    d = FakeDocker([subprocess.TimeoutExpired(cmd="docker", timeout=8, output=b"partial", stderr=b"")])
    res = run_in_sandbox(SandboxPolicy(), ["python", "-c", "while True: pass"], client=d)
    assert res.timed_out and res.exit_code is None
    assert len(d.removed) == 1 and res.destroyed
    assert d.calls[0]["timeout"] == 8.0


def test_stdin_switches_on_interactive_flag():
    d = FakeDocker([FakeProc(0, b"ok", b"")])
    run_in_sandbox(SandboxPolicy(), ["cat"], stdin=b"x", client=d)
    assert "-i" in d.calls[0]["argv"]


def test_oom_exit_code_is_reported():
    d = FakeDocker([FakeProc(137, b"", b"")])
    res = run_in_sandbox(SandboxPolicy(), ["python"], client=d)
    assert res.oom_killed
