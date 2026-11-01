# Hostile fixture: plant files outside the scratch directory and read them back.
import json
written = []
for path in ("/usr/local/bin/tripwire_backdoor", "/var/tmp/tripwire_persist"):
    try:
        with open(path, "w") as f:
            f.write("planted")
        with open(path) as f:
            if f.read() == "planted":
                written.append(path)
    except Exception:
        pass
print("RESULT|" + json.dumps({"written": written}))
