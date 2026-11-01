import pytest
from pathlib import Path
from tripwire import lab
from tripwire.lab import PAYLOADS, MODE_ORDER, build_modes, parse_result, parse_tripwire, score, summarize, run_lab
from tripwire.sandbox import SandboxPolicy, SandboxResult
from conftest import FakeDocker, FakeProc, docker_available


def res(code=0, out="", err="", dur=0.5, timed_out=False):
    return SandboxResult(code, out, err, dur, timed_out, "c", True, {})


def test_every_payload_has_a_fixture_file():
    for p in PAYLOADS:
        f = lab.HOSTILE_DIR / f"{p['id']}.py"
        assert f.exists(), f
        compile(f.read_text(), str(f), "exec")  # syntax only, never executed here


def test_eight_payloads_and_eleven_modes():
    assert len(PAYLOADS) == 8
    assert MODE_ORDER[0] == "unguarded" and MODE_ORDER[1] == "guarded"
    assert len(MODE_ORDER) == 2 + len(lab.GUARDS)


def test_modes_remove_one_guard_each_and_unguarded_has_bait():
    modes = build_modes(SandboxPolicy(), "/tmp/bait", "CANARY-x")
    assert modes["guarded"].env == {} and modes["guarded"].mounts == ()
    assert modes["unguarded"].env == {"AWS_SECRET_ACCESS_KEY": "CANARY-x"} and modes["unguarded"].mounts
    assert modes["minus_network"].network is True and modes["minus_network"].read_only is True
    assert modes["minus_secrets"].env and modes["minus_secrets"].network is False
    assert modes["minus_mounts"].mounts and modes["minus_mounts"].env == {}


def test_parse_result_and_memory_progress():
    out = "MEM|50\nMEM|100\nRESULT|{\"spawned\": 12}\n"
    p = parse_result(out)
    assert p["spawned"] == 12 and p["peak_mb_seen"] == 100


def test_parse_tripwire_events():
    ev = parse_tripwire('noise\nTRIPWIRE|{"kind": "network_connect", "detail": "x"}\nTRIPWIRE|bad\n')
    assert ev == [{"kind": "network_connect", "detail": "x"}]


BASE = SandboxPolicy()


def test_score_env_exfil_needs_the_key_to_actually_arrive():
    hits = [{"path": "/exfil", "body": "CANARY-abc"}]
    assert score("env_exfil", res(), {"secret_visible": True}, hits, 0, "CANARY-abc", BASE)["harmed"]
    s = score("env_exfil", res(), {"secret_visible": True}, [], 0, "CANARY-abc", BASE)
    assert not s["harmed"] and "never left" in s["evidence"]
    s = score("env_exfil", res(), {"secret_visible": False}, [], 0, "CANARY-abc", BASE)
    assert not s["harmed"] and s["source"] == "observed"


def test_score_file_wipe_uses_host_side_count():
    assert score("file_wipe", res(), {}, [], 5, "s", BASE)["harmed"]
    assert not score("file_wipe", res(), {}, [], 0, "s", BASE)["harmed"]


def test_score_infinite_loop_distinguishes_cap_from_watchdog():
    assert not score("infinite_loop", res(None, dur=8.1, timed_out=True), {}, [], 0, "s", BASE)["harmed"]
    assert score("infinite_loop", res(None, dur=10.1, timed_out=True), {}, [], 0, "s", BASE)["harmed"]


def test_score_fork_storm_and_memory_bomb_thresholds():
    assert not score("fork_storm", res(), {"spawned": 61}, [], 0, "s", BASE)["harmed"]
    assert score("fork_storm", res(), {"spawned": 400}, [], 0, "s", BASE)["harmed"]
    assert not score("memory_bomb", res(137), {"peak_mb_seen": 100}, [], 0, "s", BASE)["harmed"]
    assert score("memory_bomb", res(0), {"peak_mb_seen": 900}, [], 0, "s", BASE)["harmed"]


def test_score_rootfs_and_privilege_and_egress():
    assert score("rootfs_tamper", res(), {"written": ["/var/tmp/x"]}, [], 0, "s", BASE)["harmed"]
    assert not score("rootfs_tamper", res(), {"written": []}, [], 0, "s", BASE)["harmed"]
    assert score("privilege_probe", res(), {"root": True}, [], 0, "s", BASE)["harmed"]
    assert score("egress_probe", res(), {}, [{"path": "/ping", "body": ""}], 0, "s", BASE)["harmed"]
    assert not score("egress_probe", res(), {}, [], 0, "s", BASE)["harmed"]


def test_summarize_reports_what_only_one_guard_stops():
    cells = [
        {"payload": "a", "mode": "unguarded", "harmed": True, "container_destroyed": True},
        {"payload": "a", "mode": "guarded", "harmed": False, "container_destroyed": True},
        {"payload": "a", "mode": "minus_network", "harmed": True, "container_destroyed": True},
        {"payload": "b", "mode": "minus_network", "harmed": False, "container_destroyed": True},
    ]
    s = summarize(cells)
    assert s["unguarded_harmed"] == 1 and s["guarded_harmed"] == 0
    assert s["stopped_only_by"]["network"] == ["a"]
    assert s["all_containers_destroyed"]


def test_run_lab_matrix_shape_with_fake_docker():
    d = FakeDocker([FakeProc(0, b"RESULT|{\"spawned\": 5}\n", b"")] * 20)
    out = run_lab(payload_ids=["fork_storm"], mode_names=["unguarded", "guarded"], client=d)
    assert [c["mode"] for c in out["cells"]] == ["unguarded", "guarded"]
    assert len(d.calls) == 2 and all(c["stdin"] for c in d.calls)
    assert out["summary"]["guarded_harmed"] == 0


@pytest.mark.docker
@pytest.mark.skipif(not docker_available(), reason="needs a Docker daemon and the tripwire-sandbox image")
def test_real_matrix_guarded_contains_everything_unguarded_does_not():
    out = run_lab()
    s = out["summary"]
    assert s["guarded_harmed"] == 0, s["harmed_by_mode"]["guarded"]
    assert s["unguarded_harmed"] >= 6, s["harmed_by_mode"]["unguarded"]
    assert s["all_containers_destroyed"]
