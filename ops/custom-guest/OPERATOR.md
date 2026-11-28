# Custom guest operator machine

`custom-guest.sh` drives a custom SNP guest launch (spec-r9 5.4, 11). It runs on the operator machine. It reads and writes the API with the admin key and the broker with the operator key, and it runs the host phases over SSH. Two timers on that machine run the sweeper:

- **`cathedral-custom-guest-reconcile@<hotel>.timer`:** every minute it runs `custom-guest.sh sweep --hotel <hotel> --what reconcile`. That reconciles every launch of the hotel that is not finished, and turns each alert into an `OPS-ALERT` journal line.
- **`cathedral-custom-guest-wipe@<hotel>.timer`:** every 15 min it runs `custom-guest.sh sweep --hotel <hotel> --what wipe`. That removes the owner's launch folder of each returned launch once the API allows it: 72 h after the guest's stop, or at once on the owner's waiver sent after that stop (Q5).

## Where it runs

**The operator machine must be always on.** The wipe and the overdue alert run on its timers, so a laptop that sleeps or reboots cannot be the operator machine. Use the Contabo operator host.

**Every step of a launch runs on that one machine.** Its journal lives in `CG_HOME` on that machine. `reconcile` refuses with `custom_guest_journal_behind` when the API is ahead of the local journal, so a launch begun on another machine cannot be swept here. Only begin a launch where its timers run.

**One step of a hotel runs at a time.** Each step takes `CG_HOME/<hotel>/op.lock`. A step waits up to `CG_OP_LOCK_WAIT` s (120 by default). The sweeper does not wait: it skips its tick while a step runs.

## Install (once per operator machine, then once per hotel)

1. **Create the user and the folders:**

   ```sh
   useradd --system --user-group --home-dir /var/lib/cathedral-custom-guest --shell /usr/sbin/nologin cathedral-cg
   install -d -m 0755 /opt/cathedral-custom-guest
   install -d -m 0750 -g cathedral-cg /etc/cathedral/custom-guest-operator
   ```

2. **Put the checkout in place.** Clone this repository at the commit recorded with `record-versions`:

   ```sh
   git clone https://github.com/cathedralai/cathedral-sandbox /opt/cathedral-custom-guest/sandbox
   git -C /opt/cathedral-custom-guest/sandbox checkout <commit>
   ```

3. **Put the key files in place.**
   - The files are the admin key, the operator key, the host SSH key and a known-hosts file holding the host's key.
   - Copy each one into `/etc/cathedral/custom-guest-operator/` as `cathedral-cg`, with mode 0600.
   - Keys are file paths only: never put a key value in the env file, a unit or a command line.
4. **Write `/etc/cathedral/custom-guest-operator.env`** (root, 0644, paths and URLs only). Quote the values: systemd and a shell read the same file.

   ```sh
   CG_API_URL=https://api.polaris.computer
   CG_BROKER_URL=https://live.cathedral.computer
   CG_SITE_URL=https://cathedral.computer
   CG_ADMIN_KEY_FILE=/etc/cathedral/custom-guest-operator/admin.key
   CG_OPERATOR_KEY_FILE=/etc/cathedral/custom-guest-operator/operator.key
   CG_PLATFORM_GUEST=cathedral-customer-sealed
   CG_SSH="ssh -F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/cathedral/custom-guest-operator/known_hosts -i /etc/cathedral/custom-guest-operator/host.key"
   CG_SCP="scp -q -F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/cathedral/custom-guest-operator/known_hosts -i /etc/cathedral/custom-guest-operator/host.key"
   ```

5. **Install the units and start the timers for the hotel:**

   ```sh
   cp /opt/cathedral-custom-guest/sandbox/ops/custom-guest/systemd/cathedral-custom-guest-* /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now cathedral-custom-guest-reconcile@<hotel>.timer cathedral-custom-guest-wipe@<hotel>.timer
   ```

6. **Check it** (step "Heartbeat check" below). The timers must show `active`, and the first runs must leave no `OPS-ALERT` line.

**Gate:** no customer launch begins on a hotel until steps 1 to 6 are done for that hotel on the operator machine.

## Run a step by hand

Run steps as `cathedral-cg`, with the same env and `CG_HOME` as the timers, so that they share the journal and the lock:

```sh
cg() {
  sudo -u cathedral-cg bash -c 'set -a; . /etc/cathedral/custom-guest-operator.env; CG_HOME=/var/lib/cathedral-custom-guest
    exec /opt/cathedral-custom-guest/sandbox/ops/custom-guest/custom-guest.sh "$@"' cg "$@"
}
cg <step> --hotel <hotel> --launch-id <launch>
```

## Heartbeat check (read only)

Run this on the operator machine (`cg` as above):

```sh
cg check --hotel <hotel> --since-min 16
```

It sends nothing. It checks three things and prints one `OPS-ALERT` line for each finding:

- each launch the API marks `wipe_overdue`;
- each sweeper timer that is not `active`;
- each `OPS-ALERT` line the two units wrote in the last 16 minutes.

It exits 2 when it prints any alert, and 0 when there is none.

The alert lines alone can also be read from the journal:

```sh
journalctl -u 'cathedral-custom-guest-*' --since -16min -o cat | grep '^OPS-ALERT'
```

Each line reads `OPS-ALERT custom_guest hotel=<hotel> launch=<launch> <code>: <detail>`, for example `custom_guest_wipe_overdue`, `custom_guest_wipe_unsafe`, `custom_guest_hold_lost` or `custom_guest_journal_behind`.

## The owner's folder after the return (Q5)

- **The return gives the kit back at once.** R15 keeps the owner's launch folder and reports its bytes to the API (`launch_dir_bytes` in the record).
- **The capacity ledger lists the folder** (`vm-ctl.sh capacity`: `custom_guest_folders`, and `custom_guest_mib` per file system). Its blocks are already out of the file system's free space until the wipe.
- **The wipe removes only `/srv/custom-guest/<hotel>/<launch>`.**
  - It refuses a path with a link in it, or a folder this tool did not make (owner, mode, the guest's `cg-<hotel>` folders inside).
  - It never follows a link inside the folder.
- **The API marks the wipe overdue** an hour after the later of the return and the time the wipe was allowed. `reconcile` and `check` alert on it.
- **While the folder is there, the host takes no VM** (the VM capacity check refuses any VM on a custom-guest host) and no other custom launch.
