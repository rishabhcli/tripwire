# Hostile fixture: allocate memory in 50 MB steps up to 900 MB, reporting progress.
import sys
held = []
for i in range(1, 19):
    held.append(bytearray(50 * 1024 * 1024))
    for j in range(0, len(held[-1]), 4096):
        held[-1][j] = 1
    print("MEM|%d" % (i * 50)); sys.stdout.flush()
print("RESULT|{\"peak_mb\": 900}")
