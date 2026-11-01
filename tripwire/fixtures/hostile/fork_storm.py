# Hostile fixture: start up to 400 child processes (bounded so the lab host stays safe).
import json, subprocess
kids = []
try:
    for _ in range(400):
        kids.append(subprocess.Popen(["sleep", "20"]))
except Exception:
    pass
n = len(kids)
for k in kids:
    try:
        k.kill()
    except Exception:
        pass
print("RESULT|" + json.dumps({"spawned": n}))
