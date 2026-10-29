# Shared and dedicated sealed hotels

Status: design, not built. Owner of the broker changes: Eng.

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
