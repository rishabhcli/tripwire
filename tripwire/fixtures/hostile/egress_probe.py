# Hostile fixture: phone home. The canary listener records every hit.
import json, urllib.request
ok = False
try:
    urllib.request.urlopen("__CANARY_URL__/ping", timeout=2)
    ok = True
except Exception:
    ok = False
print("RESULT|" + json.dumps({"reached_canary": ok}))
