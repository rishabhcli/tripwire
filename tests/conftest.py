import subprocess
import pytest
from tripwire.sandbox import DockerClient


class FakeProc:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class FakeDocker(DockerClient):
    """Records argv; returns scripted results; never touches a real daemon."""

    def __init__(self, script=None):
        self.calls, self.removed, self.script = [], [], list(script or [])

    def run(self, argv, stdin, timeout):
        self.calls.append({"argv": argv, "stdin": stdin, "timeout": timeout})
        r = self.script.pop(0) if self.script else FakeProc()
        if isinstance(r, Exception):
            raise r
        return r

    def exists(self, name):
        return False

    def kill_and_remove(self, name):
        self.removed.append(name)


@pytest.fixture
def fake_docker():
    return FakeDocker


def docker_available():
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False
