# Shared and dedicated sealed hotels

Status: design. Built since: `reserved_for` on a hotel (in place of `dedicated_to` below), `drain`, and lend and reclaim (last section, `broker/lend.go`). Owner of the broker changes: Eng.

## Two options for a customer

| Option | What the customer gets | What keeps others out | Price shape |
|---|---|---|---|
| Shared sealed (default) | Rooms in a sealed machine that other guests also use | The AMD SEV-SNP chip keeps out the host and the operator. gVisor separates guests. | Per room-hour, no minimum |
| Dedicated sealed | A sealed machine that only this guest uses | The chip keeps out the host, the operator and all other guests. gVisor separates the guest's own rooms. | Reserved capacity, with a minimum |

A sealed machine is one SEV-SNP guest VM. Each sealed machine uses one SNP ASID on its host. The host kernel log shows the limit, for example `SEV-SNP enabled (ASIDs 1 - 99)`. So one host can run that many sealed machines, and each one can hold many rooms.

Sealing each room as its own VM is a later premium option. It costs one ASID per room, a slower start (a guest boot and attestation per room) and locked memory per room.

## How to say it

- Shared: "Your rooms run in a sealed machine. The chip keeps the host and us out."
- Dedicated: "Your rooms run in your own sealed machine. The chip keeps the host, us and other customers out."
- Do not say "each sandbox is hardware-isolated" unless the room has its own VM.

## Broker changes

1. **Hotel owner.** Add an optional `dedicated_to` field on a hotel. When it is set, the broker refuses creates on that hotel from every other guest (`403 hotel_dedicated`).
2. **Guest default.** A guest with a dedicated hotel uses it by default. Shared hotels stay available only if the guest config lists them.
3. **Drain.** Add `draining: true` on a hotel. New creates get `503 hotels_unavailable` (same code as a down hotel). Running rooms continue until delete or lifetime end.
4. **Board and quota.** The guest board and `/v1/quota` show `dedicated: true` and the drain state.

## Reclaim a dedicated sealed machine

We cannot see inside a sealed machine, so reclaim means: stop new work, let the customer save, destroy, prove.

1. **Notice.** The agreement sets the end date and the notice period.
2. **Drain.** Set `draining: true`. New creates fail with 503. Running rooms continue.
3. **Customer saves work.** Rooms end at their lifetime or the customer deletes them. Workspaces live on the sealed machine's encrypted disk. Until encrypted export exists, the customer copies out what they need before the end date.
4. **Destroy.** Stop the guest VM. Its memory and its disk key are gone, so the disk cannot be read again.
5. **Prove.** Publish a signed resource-gone receipt (`central_guest_gone`) to the customer.
6. **Re-use.** Boot a fresh sealed machine with a new identity and seal it to the next guest. Remove `dedicated_to` and `draining` for the old guest.

## Gaps before we sell dedicated widely

- Encrypted workspace export, so the customer can take data out without us.
- One command to drain and retire a dedicated hotel (today: config edit, guest stop, re-seal by hand).
- Contract terms: notice period, minimum term, data handling at the end date.
- Default network is `none` when a create omits `network` (requested on #308).

## Rollout

Config and restart of the broker. Do it in an agreed quiet window, together with other broker changes, so a live guest sees one restart, not several.

## Lend an idle dedicated machine, and take it back

A dedicated machine with no rooms is idle capacity. Lending it to the shared pool uses that capacity, but a sealed machine is one SEV-SNP guest: inside it only the room runtime separates rooms, and the chip keeps out the host, not co-tenants. A plain `reserved_for: null` and back would put the owner's rooms next to pool rooms, or next to what pool rooms left behind. The broker enforces these rules (review of #309, rules 1, 2 and 4):

1. **Whole machines only.** A lent hotel never takes the owner's rooms. The owner's creates go to its other reserved machines. A create that names the lent hotel, or that only the lent hotel would match, gets `403 hotel_lent`. The broker lends only when the owner has no rooms or creates on the machine.
2. **Reclaim means drain, destroy, re-seal, re-admit.** The broker gives the machine back only when it has no rooms and runs a new SNP launch: a `REPORT_ID` other than the one recorded at lend time. The AMD firmware sets `REPORT_ID` when it launches the guest, so a new value means a new guest VM. Nothing a pool guest left in memory, on disk or in a workspace survives.
3. **Owner in HOST_DATA.** Not built. A dedicated machine would launch with `HOST_DATA = sha256("dedicated:" + guest + ":" + epoch)` and the pool machines with the shared value, so a customer verifies "only mine" from the attestation it already fetches. It needs the host launch tooling to set HOST_DATA per machine. Until then, dedication is a broker claim, not an attested fact.
4. **No workspaces on lent machines.** Workspace creates skip a lent hotel. Reclaim destroys the machine, so a pool workspace there would end early.

### Steps (operator key)

| Step | How | Refused when |
|---|---|---|
| Lend | `PATCH /v1/broker/hotels/<id> {"lend": true}` | owner rooms or creates on it (`409 owner_rooms_active`); not reserved; not sealed; attestation fails or has no `REPORT_ID` |
| Stop new pool rooms | `PATCH {"drain": true}` | |
| Wait | Pool rooms end or are deleted | |
| Destroy and re-seal | On the host: stop the sealed guest VM and launch a fresh one with the existing tooling | |
| Re-admit | A joined hotel passes admission again (health and attestation) | |
| Reclaim | `PATCH {"reserved_for": "<owner>", "drain": false}` | rooms or creates on it (`409 rooms_active`); same `REPORT_ID` as at lend (`409 reseal_required`) |

The hotel document and the operator capacity catalog show `lent_from`; the hotel document also shows `lent_report_id` and, once attested, `admission.report_id`. Guests never see whose machine it is.

### Before a lend

- The broker checks rooms only. Workspaces, snapshots and egress secrets the owner keeps on that machine stay in it while pool guests run there, and reclaim destroys them. The owner moves them off first.

### Restarts and the fail-closed check

- A lend survives a broker restart. A joined hotel keeps it in `state_dir/hotels.json`; a hotel from the broker config file (`nc-sealed` today) keeps it in `state_dir/hotel-lends.json`, and that state wins over the config file's `reserved_for`. The broker refuses to lend a config hotel without `state_dir`, and refuses to start when `hotel-lends.json` does not parse.
- A sealed hotel reserved for an owner whose room list shows another guest's room is not the owner's alone, whatever the reason (a lost lend state, a reservation set while pool rooms ran). The broker makes it lent from the owner, logs `FAIL CLOSED`, and records the running launch's `REPORT_ID` at the next attestation, so giving it back still takes drain and a re-seal.
- After a restart, a reserved hotel takes no rooms until its first room list has passed that check.
