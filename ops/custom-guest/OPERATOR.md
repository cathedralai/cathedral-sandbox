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
   useradd --system --user-group --groups systemd-journal --home-dir /var/lib/cathedral-custom-guest --shell /usr/sbin/nologin cathedral-cg
   install -d -m 0755 /opt/cathedral-custom-guest
   install -d -m 0750 -g cathedral-cg /etc/cathedral/custom-guest-operator
   install -d -m 0700 -o cathedral-cg -g cathedral-cg /var/lib/cathedral-custom-guest
   ```

   If `/etc/cathedral` already exists with mode 0700, `cathedral-cg` cannot reach its folder inside, and every key read fails. Give traverse to that one user:

   - **Where the `acl` package is installed:** `setfacl -m u:cathedral-cg:x /etc/cathedral`. Nothing changes for any other account.
   - **Otherwise:** `chmod 0711 /etc/cathedral`, but only after this read-only check:

     ```sh
     find /etc/cathedral -mindepth 1 \( -perm -o+r -o -perm -o+x \) -printf '%m %u:%g %p\n'
     ```

     It must list nothing, or only `custom-guest-operator.env` where step 4 already ran. With `o+x` on the folder, any local account can open an entry by name when that entry's own mode lets others in, and other tools' file names there are public. If it lists anything else, take the others' access off that entry first (`chmod o-rwx`), or don't chmod.

   `systemd-journal` lets `check`, run as `cathedral-cg`, read the units' lines in the system journal. On a machine where the user already exists, add it with `usermod -aG systemd-journal cathedral-cg`. Without it, `check` alerts `custom_guest_journal_unreadable`.

2. **Put the checkout in place.** Clone this repository at the commit recorded with `record-versions`:

   ```sh
   git clone https://github.com/cathedralai/cathedral-sandbox /opt/cathedral-custom-guest/sandbox
   git -C /opt/cathedral-custom-guest/sandbox checkout <commit>
   ```

3. **Put the key files in place.**
   - The files are the admin key, the operator key, the host SSH key and a known-hosts file holding the host's key.
   - Copy each one into `/etc/cathedral/custom-guest-operator/` as `cathedral-cg`, with mode 0600.
   - Keys are file paths only: never put a key value in the env file, a unit or a command line.
   - Copy a key file to file: send it on stdin, as in `ssh <operator> 'install -m 0600 -o cathedral-cg -g cathedral-cg /dev/stdin <path>' < <file>`. Then compare the sha256 of the source file with the sha256 of the copy (`sha256sum < <path>` on the operator machine), and print only OK or FAIL. Never print the key.
   - **The host SSH key is made on the operator machine** and never leaves it: `ssh-keygen -t ed25519 -N '' -f /etc/cathedral/custom-guest-operator/host.key`, then `chown cathedral-cg:cathedral-cg` and mode 0600 on both files. Only its public half goes to the host, behind a forced command:
     - On the host, check sshd and install the dispatcher from the host checkout, in one line so a failed check installs nothing: `python3 -I <repo dir on the host>/ops/custom-guest/cg_ssh_dispatch.py --check-sshd --addr <operator address> --laddr <host address> && install -m 0755 -o root -g root <repo dir on the host>/ops/custom-guest/cg_ssh_dispatch.py /usr/local/sbin/cathedral-cg-dispatch`.
     - The check reads `sshd -T -C` for this key's own login: root, from the operator address, to the host address `hosts.conf` uses, on port 22 (`--lport` if not), so `Match Address`, `LocalAddress` and `LocalPort` blocks count. Add `--rdomain <name>` if sshd listens in a routing domain, so `Match RDomain` blocks count too. Both must be plain IP addresses, with no `%` scope. `--laddr` is the address sshd sees on its own side of the connection: behind NAT that is the host's private address, not the one the operator machine dials. `AcceptEnv` may hold only `LANG`, `LC_*`, `COLORTERM`, `NO_COLOR` and `TZ`, exactly as written, and `PermitUserEnvironment` must be `no`. Any other pattern fails, a narrower one such as `LC_ALL` included. It prints `OK sshd` or one `FAIL sshd` line per problem. sshd hands the variables it accepts to root's shell, which runs before the dispatcher, so the dispatcher's fixed environment cannot undo them. Run the check again after any sshd config change.
     - Add the key to root's `authorized_keys` there as `command="/usr/local/sbin/cathedral-cg-dispatch <hotel> <sha7>",from="<operator address>",restrict <public key>`. `<sha7>` is the host checkout's (`/opt/cathedral/cathedral-sandbox-cg-<sha7>`, as in `hosts.conf`).
     - The key then runs only that checkout's host tool, with the phases and options `custom-guest.sh` sends, and the intake upload (`scp -t` into the launch's inbox). Everything else is refused with one line, exit 1, including a login shell and sftp: sshd runs the forced command in place of the sftp subsystem too. The tool runs with a fixed environment, nothing from the client.
     - When the host checkout changes, update `<sha7>` in the line (and reinstall the dispatcher from the new checkout).
   - **Take the host's key for `known_hosts` over a session you already trust**, for example `cat /etc/ssh/ssh_host_ed25519_key.pub` on the host. Do not use `ssh-keyscan` from the operator machine. Write the line as `<host address> ssh-ed25519 AAAA...`: it starts with the same host address as `hosts.conf`, and the `.pub` file's trailing comment is dropped.
4. **Write `/etc/cathedral/custom-guest-operator.env` and `hosts.conf`.** The env file is root, 0644, paths and URLs only. Quote the values: systemd and a shell read the same file.

   ```sh
   CG_API_URL=https://api.polaris.computer
   CG_BROKER_URL=https://live.cathedral.computer
   CG_SITE_URL=https://cathedral.computer
   CG_ADMIN_KEY_FILE=/etc/cathedral/custom-guest-operator/admin.key
   CG_OPERATOR_KEY_FILE=/etc/cathedral/custom-guest-operator/operator.key
   CG_PLATFORM_GUEST=cathedral-customer-sealed
   CG_SSH="ssh -F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/cathedral/custom-guest-operator/known_hosts -i /etc/cathedral/custom-guest-operator/host.key"
   CG_SCP="scp -q -O -F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/cathedral/custom-guest-operator/known_hosts -i /etc/cathedral/custom-guest-operator/host.key"
   ```

   Then write `/var/lib/cathedral-custom-guest/hosts.conf` (`cathedral-cg`, 0600), one line per hotel:

   ```
   <hotel> root@<host address> <repo dir on the host> <public host>
   ```

   The repo dir is a checkout of this repository on the host, at the same commit, at `/opt/cathedral/cathedral-sandbox-cg-<sha7>` (the forced command runs only that path). Make it root's alone: `chown -R root:root /opt/cathedral/cathedral-sandbox-cg-<sha7>`, then `chmod -R go-w /opt/cathedral/cathedral-sandbox-cg-<sha7>` (a `git archive` extracted as root keeps its 0775 and 0664 modes), and `/opt/cathedral` itself root-owned and not group- or other-writable. On every call the forced command checks the whole checkout, since root runs the Python tool, its siblings, the kit scripts and the `snp_qemu.py` link into `room-kit`. One file or folder owned by another user or writable by group or others, or a link out of the checkout, refuses every phase, and the refusal names the path. `CG_SCP` keeps `-O`: plain scp asks for sftp, which the forced command refuses. **Keep it on the host as long as the timers run:** `check` calls its `folders` phase on every heartbeat, and the wipe and the return's R15 need it.

5. **Install the units and start the timers for the hotel.** Start them only once the lane is on: `CATHEDRAL_CUSTOM_GUEST_ENABLED`, with the hotel and the owner listed. While the lane is off, the API's list answers 404, so every reconcile tick alerts. Keep the lane on until the last launch's `wiped_at`.

   ```sh
   cp /opt/cathedral-custom-guest/sandbox/ops/custom-guest/systemd/cathedral-custom-guest-* /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now cathedral-custom-guest-reconcile@<hotel>.timer cathedral-custom-guest-wipe@<hotel>.timer
   ```

6. **Check it** (step "Heartbeat check" below), after the wipe timer's first tick (it runs at :00, :15, :30 and :45). The timers must show `active`, both units must have a run line, and the first runs must leave no `OPS-ALERT` line. This is the positive control for the journal read: a check that reads nothing alerts.

**Gate:** no customer launch begins on a hotel until steps 1 to 6 are done for that hotel on the operator machine.

## Run a step by hand

Run steps as `cathedral-cg`, with the same env and `CG_HOME` as the timers, so that they share the journal and the lock:

```sh
cg() {
  sudo -u cathedral-cg bash -c 'set -a; . /etc/cathedral/custom-guest-operator.env; CG_HOME=/var/lib/cathedral-custom-guest; cd /
    exec /opt/cathedral-custom-guest/sandbox/ops/custom-guest/custom-guest.sh "$@"' cg "$@"
}
cg <step> --hotel <hotel> --launch-id <launch>
```

## Heartbeat check (read only)

Run this on the operator machine (`cg` as above):

```sh
cg check --hotel <hotel> --since-min 16
```

It sends nothing. It reads the API's list, the host's launch folders (one read-only `folders` call over SSH), the timers and the journal. It prints one `OPS-ALERT` line for each finding:

- each launch the API marks `wipe_overdue`;
- each launch folder on the host that the API does not list (`custom_guest_folder_unlisted`): no sweep wipes it;
- each sweeper timer that is not `active`;
- a journal that `cathedral-cg` cannot read (`custom_guest_journal_unreadable`), or a unit that wrote no run line in the window (`custom_guest_sweeper_silent`). An empty read never passes as a quiet one;
- each `OPS-ALERT` line the two units wrote in the last 16 minutes.

It exits 2 when it prints any alert, and 0 when there is none.

**Someone must run it.** The alerts land only in the operator machine's journal, and nothing posts them anywhere. Run the check from the team's heartbeat over SSH, and treat exit 2 as an alert. `cg` is a shell function, so over SSH send the full line:

```sh
ssh <operator> "sudo -u cathedral-cg bash -c 'set -a; . /etc/cathedral/custom-guest-operator.env; CG_HOME=/var/lib/cathedral-custom-guest; cd /
  exec /opt/cathedral-custom-guest/sandbox/ops/custom-guest/custom-guest.sh check --hotel <hotel> --since-min 16'"
```

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
- **Keep the hotel and the owner listed until `wiped_at`.** The sweeper and the wipe route find a launch only while `CATHEDRAL_CUSTOM_GUEST_HOTELS` lists its hotel and `CATHEDRAL_CUSTOM_GUEST_SCOPES` lists its owner. Take either off only after the launch's record shows `wiped_at`. `check` alerts on a folder left behind.
- **The waiver counts only after the stop.** The owner sends `waive_notice: true` after the guest's last stop and before (or with) the return. A waiver sent while the guest still runs does not allow the wipe, and the folder waits the 72 h.
- **The host tool must be from Q5 on.** `return` refuses R15 (`custom_guest_hold_unsupported`, "deploy the host tool first") when the host's facts carry no `launch_dir_bytes`: an older host tool would remove the folder at R15, and the API would record a wipe that never waited. Deploy the host tool, then `resume`.

## The hold and a live room

A hold drains the hotel (H2), then fences it (H3). The broker refuses the fence (409 `rooms_active`) while any room still runs on the hotel. The operator retries for `CG_FENCE_WAIT` seconds (1800 by default), and all that time **the hotel stays drained**: it takes no new room. Then the hold aborts with `custom_guest_barrier_failed` and restores the drain. The room is not touched.

- For a hold you watch, set `CG_FENCE_WAIT` lower (E2E route 1 used 30 for the live-room test).
- Before a hold, check the broker's `rooms_in_use` is 0. If not, wait or ask the owner to end the rooms first.
