# Anchor miner hotel: re-offer, restart and reboot runbook

Operator runbook for the production miner hotel that anchors one of our SN94 UIDs
(AB#822, spec section 5.3). The hotel is a `SEALED_MINER=1` sealed guest; Polaris
admits it only on an offer signed by the UID's hotkey that names this boot's
`binding_sha256`. Every guest boot (and every receipts restart) is a new binding, so
the old offer is refused (`binding_differs_from_offer`), the broker drains, deletes and
rejoins the hotel, and the rejoin needs a new signed offer. `hotel-offer-refresh` (R1)
posts that offer by itself. This runbook covers what R1 cannot.

Placeholders: `$BROKER` the broker base URL, `$POLARIS` the Polaris API base URL,
`$HOTEL` the broker hotel id (`miner-<machine prefix>`, as the reconciler names it),
`$MACHINE` the 64-hex `machine_id` (in `/var/lib/cathedral-anchor/offer-state.json` and
in every `binding_changed` journal line). The operator key is read from a root-only
file into a shell variable and never echoed: `OP=$(cat /root/.broker-operator-key)`.

## 1. Install R1 on the hotel's host

R1 needs the anchored UID's hotkey seed on this host (decision D4). The coldkey never
leaves the wallet.

1. Kit and Python: copy `room-kit/` to `/opt/cathedral-anchor/room-kit`, then
   `python3 -m venv /opt/cathedral-anchor/venv` and
   `/opt/cathedral-anchor/venv/bin/pip install py-sr25519-bindings==0.2.2 cryptography`.
2. Hotkey: `install -d -m 0700 /etc/cathedral-anchor`, then put the hotkey file (plaintext
   Bittensor hotkey JSON or `0x` hex seed) at `/etc/cathedral-anchor/hotkey`, owner root,
   mode 0600. R1 refuses a file readable by group or others (`hotkey_file_refused`, exit 1).
3. Config: copy `room-kit/hotel-offer-refresh/hotel-offer-refresh.env.example` to
   `/etc/cathedral-anchor/refresh.env` (mode 0600) and set the public origin, the guest
   attestation URL (`https://<SEALED_GUEST_IP>:<SEALED_MINER_TLS_PORT>`), the Polaris offer
   URL and the paths. Paths and URLs only: no key material in this file.
4. Units: copy `hotel-offer-refresh.service` and `hotel-offer-refresh.timer` to
   `/etc/systemd/system/`, `systemctl daemon-reload`,
   `systemctl enable --now hotel-offer-refresh.timer`.
5. Check: `systemctl start hotel-offer-refresh.service`, then
   `journalctl -u hotel-offer-refresh -n 20`. The first run shows `binding_changed old=none`
   and `offer_posted`. Later runs with the same binding print nothing.

What R1 does every 5 minutes: reads `GET /room/attestation` from the guest, checks it
with `hotel_offer.py` (binding digest, REPORT_DATA, chip, the TLS key that answered),
compares `binding_sha256` with the state file, and on a change signs an offer with
sequence = current unix seconds and posts it. A refused or failed POST is retried with
backoff, each try with a newer sequence; the next timer run tries again after that. A
lost state file costs one extra post, never `offer_sequence_not_newer`.

| Journal line | Meaning |
|---|---|
| `binding_changed old=<sha\|none> new=<sha> machine=<id>` | The guest booted again (or receipts restarted). The alert line for section 3. |
| `offer_posted binding=<sha> sequence=<n> offer_id=<id>` | Polaris accepted the offer. |
| `offer_refused attempt=<i> of=<n> reason=<...>` | One try refused (the reason is the API's short code). |
| `offer_failed` (exit 3) | Every try refused; the next run tries again. |
| `attestation_unavailable` (exit 2) | The guest does not answer or failed a check (down, booting). |
| `hotkey_file_refused`, `config_refused` (exit 1) | Fix the host; nothing is posted. |

R1 cannot see rooms. Whether a reboot left live rooms behind is read from the broker
(section 3).

## 2. Planned restart (recovers by R1 alone)

1. Drain: `curl -sS -X PATCH -H "Authorization: Bearer $OP" -d '{"drain":true}' "$BROKER/v1/broker/hotels/$HOTEL"`.
   Use the operator drain only for a planned restart: it becomes a sticky `operator_hold`
   in Polaris, cleared in step 5.
2. Wait until the hotel is empty: the customer rooms end on their own or are stopped by
   their owners. `curl -sS -H "Authorization: Bearer $OP" "$BROKER/v1/broker/hotels/$HOTEL"`.
   A plain leave refuses while rooms remain (`hotel_not_empty`).
3. Restart the guest: `systemctl restart room-sealed-<name>.service` (or the host).
4. R1 sees the new binding within 5 minutes and posts the offer (`binding_changed`,
   `offer_posted`).
5. Clear the hold so the reconciler may replace the drained hotel:
   `curl -sS -X POST -H "Authorization: Bearer $OP" "$POLARIS/v1/cathedral/snp/hotel-offers/$MACHINE/clear-hold"`.
   The reconciler then deletes the empty old hotel and joins the new boot.
6. Check: `GET $BROKER/v1/broker/capacity` (operator key) lists `$HOTEL` with `up: true`
   and `drain: false`.

## 3. Unplanned reboot with live rooms

The broker never learns that a rebooted guest's rooms died, and refuses to delete a
hotel that still holds rooms (`hotel_not_empty`). Until the rooms are forgotten, the new
boot (same chip, same hotel id) waits on `hotkey_cap_until_drained`, even though R1 has
already posted its offer. Only the operator key can forget the rooms (the enroll key
cannot), and only after the hotel has been down 10 minutes.

Trigger: a `binding_changed` journal line nobody planned.

1. Read the hotel: `curl -sS -H "Authorization: Bearer $OP" "$BROKER/v1/broker/capacity"`
   and find `$HOTEL`: `up`, `drain`, `down_since`.
   - Hotel gone, or rejoined with `up: true`: it was empty; R1 and the reconciler
     already recovered it. Done.
   - Hotel listed with `up: false`: its rooms are lost. Go on.
2. Wait until `down_since` is 10 minutes or more in the past. The broker refuses the
   forget before that ("the hotel has been down ...; wait until 10m0s").
3. If `drain` is false (the reconciler has not drained it; the Polaris roster grace can
   hold off its drain for up to 3 h), drain it with the operator key:
   `curl -sS -X PATCH -H "Authorization: Bearer $OP" -d '{"drain":true}' "$BROKER/v1/broker/hotels/$HOTEL"`.
   The broker refuses the forget on an undrained hotel ("drain the hotel first").
4. Forget the rooms and remove the hotel:
   `curl -sS -X DELETE -H "Authorization: Bearer $OP" "$BROKER/v1/broker/hotels/$HOTEL?forget_rooms=true"`.
   A refusal names its reason; the old guest answering, or a room call it answered
   since it went down, means its rooms are not lost: stop and look.
5. Clear the hold. An operator drain (step 3) became a sticky `operator_hold` the
   reconciler never deletes and keeps counting against the hotkey cap; clear it even if
   step 3 was skipped, it is harmless then:
   `curl -sS -X POST -H "Authorization: Bearer $OP" "$POLARIS/v1/cathedral/snp/hotel-offers/$MACHINE/clear-hold"`.
6. Check R1 posted the new boot's offer (`journalctl -u hotel-offer-refresh`:
   `offer_posted` for the new binding; if not, `systemctl start hotel-offer-refresh.service`).
   The reconciler joins the new boot on its next pass. Check `GET $BROKER/v1/broker/capacity`:
   `$HOTEL` with `up: true`, `drain: false`.

Billing for the lost rooms: Polaris ends a room's counted time at the broker's
hotel-unreachable mark (AB#822 P1), so the dead hotel is not paid for room-hours nobody
received, before or after the forget.

## 4. Without the hotkey on the host

If D4 is refused, R1 is not installed. Every boot then needs the wallet holder to sign
by hand on a machine with the hotkey:
`python3 room-kit/hotel_offer.py --origin <public origin> --attestation-url <guest url> --hotkey-file <hotkey> --post <polaris offers url>`.
The hotel is out of placement until that offer lands. Sections 2 (steps 1 to 3, 5, 6)
and 3 still apply.
