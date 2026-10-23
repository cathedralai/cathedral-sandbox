# CONST limits + Reliquary guest — plug-and-play (waits on Fred’s operator key)

Eng cannot call `GET/PATCH /v1/broker/guests` without the live broker **operator** Bearer (`401 operator key required`). Guest keys cannot edit `config.json` on the host either.

This pack is everything else. When Fred hands `BROKER_OPERATOR_KEY` (and, for a new Reliquary guest, the raw API key + view token to hash — or the hashes themselves), go-live is one script + the stage B restart.

**Live today (Eng-verified):** `const` answers quota 200 with `max_rooms=1000`, `max_creates_per_minute=600`, `default_sealed=true`, hotels `nc,c46,c48,nc-sealed` (green unavailable). Target raise matches Affine-shaped onboard: **4000 rooms / 600 creates/min**.

---

## A. `config.json` edits (on broker host, before stage B restart)

Hashes only in the file. Never commit raw keys. Mint Reliquary key+view off-box (1Password), then:

```bash
# on any trusted machine with the raw secrets in env (not Discord)
python3 - <<'PY'
import hashlib, os
for name in ("RELIQUARY_API_KEY", "RELIQUARY_VIEW_TOKEN"):
    v = os.environ[name].strip()
    print(name, hashlib.sha256(v.encode()).hexdigest())
PY
```

Drop / replace these guest objects under `"guests"` in `/etc/thin-broker/config.json` (keep other guests untouched). Replace the `<…>` placeholders:

```json
{
  "id": "const",
  "key_sha256": "<existing const key sha256 — do not rotate unless Fred says>",
  "view_token_sha256": "<existing const view sha256>",
  "max_rooms": 4000,
  "max_creates_per_minute": 600,
  "default_sealed": true,
  "hotels": ["green", "nc", "c46", "c48", "nc-sealed"]
},
{
  "id": "reliquary",
  "key_sha256": "<sha256 of new Reliquary API key>",
  "view_token_sha256": "<sha256 of new Reliquary view token>",
  "max_rooms": 1000,
  "max_creates_per_minute": 600,
  "default_sealed": true,
  "hotels": ["nc-sealed", "c46", "c48"]
}
```

Notes:

- `green` is listed for CONST so it comes back when the hotel is restored; creates that need green will 503/`hotels_unavailable` until then.
- Reliquary stays on sealed-capable hotels only (no bare Affine blast claim).
- Runtime PATCH alone dies on restart — **config.json is the durable source**. PATCH after restart is the fast confirm + guard.

Backup before edit: `cp -a /etc/thin-broker/config.json /etc/thin-broker/config.json.bak.$(date -u +%Y%m%dT%H%M%SZ)`.

---

## B. After stage B restart — operator PATCH + guards

```bash
export BROKER=https://live.cathedral.computer
export BROKER_OPERATOR_KEY='…'   # Fred hands this; never commit

# 1) see guests (must be 200)
curl -sS -H "Authorization: Bearer $BROKER_OPERATOR_KEY" \
  "$BROKER/v1/broker/guests" | python3 -m json.tool | head -80

# 2) raise const in memory (matches config; safe if already 4000)
curl -sS -X PATCH -H "Authorization: Bearer $BROKER_OPERATOR_KEY" \
  -H "Content-Type: application/json" \
  "$BROKER/v1/broker/guests/const" \
  -d '{"max_rooms":4000,"max_creates_per_minute":600,"default_sealed":true,"hotels":["green","nc","c46","c48","nc-sealed"]}'

# 3) const guard
curl -sS -H "Authorization: Bearer $CONST_KEY" "$BROKER/v1/quota" \
  | python3 -c 'import json,sys; g=json.load(sys.stdin)["guest"]; assert g["max_rooms"]==4000 and g["max_creates_per_minute"]==600, g; print("const limits ok", g)'

# 4) reliquary guard (after Fred hands RELIQUARY_KEY)
curl -sS -H "Authorization: Bearer $RELIQUARY_KEY" "$BROKER/v1/quota" \
  | python3 -c 'import json,sys; g=json.load(sys.stdin)["guest"]; assert g["id"]=="reliquary", g; print("reliquary guest ok", g)'

# 5) tiny smoke each (deny_all)
for KEYNAME in CONST_KEY RELIQUARY_KEY; do
  KEY="${!KEYNAME}"
  SID=$(curl -sS -X POST "$BROKER/v1/sandboxes" \
    -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
    -d '{"image":"alpine:3.20","vcpus":1,"memory_mib":256,"network":{"mode":"deny_all"}}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  echo "$KEYNAME created $SID"
  curl -sS -X POST "$BROKER/v1/sandboxes/$SID/exec" \
    -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
    -d "{\"cmd\":[\"echo\",\"${KEYNAME}_OK\"]}"
  curl -sS -o /dev/null -w "$KEYNAME delete %{http_code}\n" -X DELETE \
    -H "Authorization: Bearer $KEY" "$BROKER/v1/sandboxes/$SID"
done
```

Or one shot: `BROKER_OPERATOR_KEY=… CONST_KEY=… RELIQUARY_KEY=… ./scripts/const_reli_go_live.sh`

---

## C. What Fred still owns

| Item | Who |
| --- | --- |
| Live broker operator Bearer | Fred → Eng or Spock runs PATCH |
| Mint Reliquary API key + view token (or supply sha256s) | Fred |
| Edit `/etc/thin-broker/config.json` + stage B restart | Spock / Fred (Eng has no host SSH for this from the laptop) |
| Hand Reliquary key to Reli out of band | Fred |

Eng will not paste operator or Reliquary secrets into Discord or git.
