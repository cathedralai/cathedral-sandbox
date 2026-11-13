# Broker pin patch rendered by roll.sh pin-patch. Add only: changes nothing but sealed_measurements,
# removes nothing. Usage (via broker_swap_config.sh): python3 patch.py <config.json>
import json
import sys

# (current, new) per staged hotel. A list, not a dict: hotels sharing a current build keep every new one.
PAIRS = []  # __PAIRS__
path = sys.argv[1]
c = json.load(open(path))
frozen = json.dumps({k: v for k, v in c.items() if k != "sealed_measurements"}, sort_keys=True)
pins = c.get("sealed_measurements")
if not isinstance(pins, list) or not c.get("amd_verifier"):
    sys.exit("refuse: no pin list or no amd_verifier")
have = {str(x).strip().lower() for x in pins}
missing = sorted({cur[:8] for cur, _ in PAIRS if cur not in have})
if missing:
    sys.exit("refuse: a current build is not pinned (%s); re-read the baseline" % ", ".join(missing))
before = len(pins)
for _, new in PAIRS:
    if new not in {str(x).strip().lower() for x in pins}:
        pins.append(new)
if json.dumps({k: v for k, v in c.items() if k != "sealed_measurements"}, sort_keys=True) != frozen:
    sys.exit("refuse: the patch changed more than sealed_measurements")
if not have <= {str(x).strip().lower() for x in pins}:
    sys.exit("refuse: a pin was removed")
with open(path, "w") as f:
    json.dump(c, f, indent=2)
    f.write("\n")
print("sealed_measurements:", before, "->", len(pins), "| new builds pinned, every current pin kept")
