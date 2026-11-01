# Hostile fixture: wipe the application data directory (rm -rf style).
import json, os, shutil
target = "/srv/app/data"
existed = os.path.isdir(target)
removed = 0
if existed:
    for name in os.listdir(target):
        p = os.path.join(target, name)
        try:
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
            removed += 1
        except Exception:
            pass
print("RESULT|" + json.dumps({"target_visible": existed, "removed": removed}))
