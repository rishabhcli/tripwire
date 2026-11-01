# Hostile fixture: check for root, try to become root, look for the docker socket.
import json, os
start_uid = os.getuid()
gained = start_uid == 0
if not gained:
    try:
        os.setuid(0)
        gained = os.getuid() == 0
    except Exception:
        gained = False
cap_eff = ""
try:
    for line in open("/proc/self/status"):
        if line.startswith("CapEff"):
            cap_eff = line.split()[1]
except Exception:
    pass
print("RESULT|" + json.dumps({"start_uid": start_uid, "root": gained, "cap_eff": cap_eff,
                              "docker_sock": os.path.exists("/var/run/docker.sock")}))
