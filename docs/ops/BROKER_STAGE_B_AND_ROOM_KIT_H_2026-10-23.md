# Stage B (broker binary) + Stage H (room kit at pin 99e0cc2)

Plug-and-play for Spock / Fred. Eng prepared this so a live operator key is not required for the swap itself; guest-limit PATCH still needs the operator Bearer (see CONST/Reliquary pack).

**Pins**

| What | Value |
| --- | --- |
| Broker build tip (main after #312) | `1363af4d64e654d3d75837ee2948a9de5c65cec9` |
| Hotel API / room-kit pin | `99e0cc2` (`room-kit/versions.lock` → `CATHEDRAL_COMMIT`) |
| Broker host | Genoa `185.191.116.231` — `thin-broker.service` → `/usr/local/bin/thin-broker -config /etc/thin-broker/config.json` |
| Do **not** restart | `affine-sandbox-api.service` on the same host |

Optional later tip: `fix/broker-isolation-honesty` (`c3563f7`) adds fail-closed missing-network + `isolation` on room answers. Prefer main `1363af4d` first unless Fred wants that in the same window.

---

## Stage B — broker binary swap

Stop at the first failed check. Rooms keep running across restart; ownership rebuilds from `broker_guest` labels.

```bash
# on broker host, as root
set -euo pipefail
PIN=1363af4d64e654d3d75837ee2948a9de5c65cec9
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
SRC=/opt/cathedral-sandbox   # or wherever the checkout lives; clone if missing

cd "$SRC"
git fetch origin
git checkout --detach "$PIN"

# BEFORE swap: apply CONST + Reliquary config.json edits from
# docs/ops/CONST_LIMITS_RELIQUARY_GUEST_PLUGPLAY_2026-10-23.md
# (hashes only — never paste raw keys into chat)

cp -a /usr/local/bin/thin-broker "/usr/local/bin/thin-broker.bak.$STAMP"
cp -a /etc/thin-broker/config.json "/etc/thin-broker/config.json.bak.$STAMP"

cd broker
go version   # need >= 1.26.10
go build -o /tmp/thin-broker."$STAMP" .
install -o thinbroker -g thinbroker -m 0755 /tmp/thin-broker."$STAMP" /usr/local/bin/thin-broker

systemctl restart thin-broker.service
systemctl is-active thin-broker.service
curl -sS -m 5 http://127.0.0.1:18100/healthz
journalctl -u thin-broker.service -n 30 --no-pager
# expect: central booking on 127.0.0.1:18100: N hotels, M guests
```

**Guards (from any machine with guest/ops keys):**

```bash
BROKER=https://live.cathedral.computer
# guest path still 200
curl -sS -o /dev/null -w 'quota %{http_code}\n' \
  -H "Authorization: Bearer $CONST_KEY" "$BROKER/v1/quota"

# one ops create → exec → delete (ops key)
SID=$(curl -sS -X POST "$BROKER/v1/sandboxes" \
  -H "Authorization: Bearer $OPS_KEY" -H "Content-Type: application/json" \
  -d '{"image":"alpine:3.20","vcpus":1,"memory_mib":256,"network":{"mode":"deny_all"},"sealed":false}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -sS -X POST "$BROKER/v1/sandboxes/$SID/exec" \
  -H "Authorization: Bearer $OPS_KEY" -H "Content-Type: application/json" \
  -d '{"cmd":["echo","ok"]}'
curl -sS -o /dev/null -w 'delete %{http_code}\n' -X DELETE \
  -H "Authorization: Bearer $OPS_KEY" "$BROKER/v1/sandboxes/$SID"

# guest receipts page filtered
curl -sS -H "Authorization: Bearer $CONST_KEY" \
  "$BROKER/v1/hotels/nc/receipts" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); assert d.get("filtered") is True and "scanned" in d, d; print("receipts ok", d.get("scanned"))'
```

**Rollback:** `cp /usr/local/bin/thin-broker.bak.$STAMP /usr/local/bin/thin-broker && systemctl restart thin-broker.service` (and restore `config.json.bak` if guest edits were bad).

---

## Stage H — room kit re-run at pin `99e0cc2`

One hotel at a time. `install.sh` refuses when the hotel still has live rooms.

**Order:** green (already down) → then whichever of nc / c46 / c48 has the fewest resident rooms and can drain to zero.

```bash
# on the hotel host
set -euo pipefail
PIN=1363af4d64e654d3d75837ee2948a9de5c65cec9   # kit tree that pins API 99e0cc2
SRC=/opt/cathedral-sandbox
cd "$SRC" && git fetch origin && git checkout --detach "$PIN"
cd room-kit
# confirm pin
grep '^CATHEDRAL_COMMIT=' versions.lock   # must print 99e0cc2
test -f dist/cathedral-99e0cc2.tar.gz || ./make-dist.sh 99e0cc2

# only when free / no live rooms:
./install.sh room.env

# checks
curl -sS -H "Authorization: Bearer $HOTEL_KEY" "$HOTEL_API/v1/rooms" | head
# egress: new rooms show port_bound; probe passes
# via broker: one ops room deny_all + one allowlist create/exec/delete
```

**Rollback:** re-run `install.sh` from the previous checkout.

**Not in this pass (stage S):** dedicated sealed hotel rebuild = new measurement, ends all rooms on that guest, needs a customer window and a published expected measurement.

---

## Evidence to keep

- Stage B: binary backup path, `healthz`, journal line with hotel/guest counts, guard HTTP codes, receipts `filtered`/`scanned`.
- Stage H: hotel id, install exit 0, probe pass, one deny_all + one allowlist ops room.
