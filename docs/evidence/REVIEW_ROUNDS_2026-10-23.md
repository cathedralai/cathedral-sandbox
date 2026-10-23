# Review rounds 1 to 5, 2026-10-23

Scope: the broker, the hotel API, the room kit (egress, receipts, install)
and the sealed kit, at PR #311. Each finding was checked against the source.
A fix has a test that failed before it. "Customer path" means the code that a
live customer's requests pass through: the broker, the shared hotels and the
dedicated sealed hotel.

Status:

- **Fixed**: in #310 or #311, lands with the deploy stage named.
- **Pending**: needs a design or an owner decision; not in #311.
- **Doc**: by design; the docs now say so.

Deploy stages (see the plan at the end): **B** broker restart, **H** shared
hotel reinstall, **S** sealed hotel rebuild, **T** client tool (on merge).

## Findings

| # | What breaks, in plain terms | Customer path | Status | Lands at |
|---|---|---|---|---|
| B1 | One guest's bad request rested a hotel for every guest | Yes | Fixed | B |
| B2 | Allowlist `host:443` refused: hotels ran old API code | Yes | Fixed | H, S |
| B3 | Two tests expected the old allowlist rule | No | Fixed | merge |
| B4 | The ops probe could start a room on a dedicated hotel | Yes | Fixed | B |
| B5 | `host:443` also opens port 80 | Yes | Doc | |
| B6 | A bare IP opens every port | Yes | Doc | |
| B7 | Harbor path ignores the hotel choice | No | Pending | |
| B8 | A guest's filtered receipts view cannot be tested from outside | Yes | Logic verified | |
| B9 | B1's fix stopped resting a hotel whose own key was wrong | Yes | Fixed | B |
| B10 | Image import warmed every hotel, dedicated ones too | Yes | Fixed | B |
| B11 | Bulk delete reached every hotel, dedicated ones too | Yes | Fixed | B |
| B12 | An ops key could read a dedicated hotel's receipts | Yes | Fixed | B |
| B13 | A guest's own bulk-delete receipt was hidden from it | Yes | Fixed | B |
| B14 | A fake image name rested a hotel for everyone | Yes | Fixed | B |
| B15 | A network change with no mode opened the internet (hotel) | Yes | Fixed | H, S |
| B16 | A fork of a `deny_all` room gets internet unless `network` is set again | Yes | Pending (design) | |
| B17 | B14's fix also excused the hotel's own registry faults | Yes | Fixed | B |
| B18 | Same as B15, on the Harbor path | Yes | Fixed | B |
| B19 | Narrowing a guest's hotel list leaves its rooms on the old hotels | No | Pending | |
| B20 | A room whose bridge port was not found escaped the network guard | Yes | Fixed (fails closed) | H, S |
| B21 | Expired, bulk-deleted and restart-removed rooms get no delete receipt | Yes | Pending (design); doc states it | |
| B22 | A receipts-service restart starts a new key; the broker then serves only the new binding | Yes | Pending (design); doc states it | |
| B23 | A room could link its process log to the hotel API key and read it | Yes | Fixed | H, S |
| B24 | An API restart forgets every room and removes their containers | Yes | Phase 1 fixed (install refuses while rooms are live); phase 2 pending (adopt rooms on start) | H |
| B25 | Files outside `/work` answered 200 but never reached the room | Yes | Fixed (400 `path_outside_work`) | H, S |
| B26 | Any guest key sees chain-wide hotel counters on `/v1/broker/stats` and the live board | Yes | Pending (low) | |
| B27 | A wrong hotel key shows the guest a 401, as if its own key failed | Yes | Pending (low) | |
| B28 | A guest's filtered receipt chain failed `verify_receipts.py` | Yes | Fixed | B, T |
| B29 | A dedicated sealed hotel takes only `"sealed": true` creates | Yes | Doc | |
| B30 | Refused creates (no room id) are receipted but no guest can see them | Yes | Pending (low) | |
| B31 | Debug sealed builds never started SSH | No | Fixed | S |
| B32 | Guest receipt paging stopped after 10,000 hotel receipts and still said PASS | Yes | Fixed | B, T |
| B33 | `filtered` is a server-set flag; `head` is not signed, so no chain proves nothing is missing | Yes | Doc; verifier output says what it checked | T |
| B34 | The new install guard exited with no message when the room daemon was down | No | Fixed | H |
| B35 | A failed re-install in auto mode could leave room networks without egress rules | Yes | Fixed | H |
| B36 | The verifier passed a debug sealed build (host has root SSH) | Yes | Fixed | T |
| B37 | A sealed install whose measurement differed still said "done" | No | Fixed | S |
| B38 | The files API checked a path, then opened it again: a room could swap in a link and read the hotel API key | Yes | Fixed | H, S |
| B39 | A build context URL could reach cloud metadata or host services by DNS rebinding or redirect | Yes | Fixed | H, S |
| B40 | `disk_gib` is not enforced for writes to `/work` from inside the room; one room can fill the shared volume | Yes | Pending (design: XFS project quota per room) | |
| B41 | In an image with no `timeout` binary, an exec past its limit keeps running | Yes | Pending | |
| B42 | Image builds are not under the room's network policy | Yes | Pending (design) | |
| B43 | An image reference could start with `-` and read as a docker flag | Yes | Fixed | H, S |
| B44 | Stopping a background process can miss its children | Yes | Pending (low) | |
| B45 | Room egress rules are IPv4 only; IPv6 is not disabled on room bridges | Yes | Observation: a live room has no IPv6 address and cannot add one (gVisor). Hardening pending | |
| B46 | Allowlists accepted private, host and reserved ranges (`169.254.169.254`, `0.0.0.0/0`) | Yes | Fixed | H, S |
| B47 | The host holds the sealed hotel's API key, and broker to guest traffic is plain HTTP on the tap | Yes | Doc fixed; pending (design: TLS into the guest, key made in the guest) | |
| B48 | A write whose answer was lost was sent to the API again: an exec could run twice | Yes | Fixed | H, S |
| B49 | A chunked request body was signed as empty | No (broker sends lengths) | Fixed (411) | H, S |
| B50 | Bad `after`/`limit` on the receipts route was a 500 | No | Fixed (400) | H, S |
| B51 | The verifier does not pin the AMD ARK by default and has no TCB floor | Yes | Pending; doc states it | |
| B52 | Harbor file, tar and stat errors showed the hotel's private API URL | Yes | Fixed | B |
| B53 | One guest's long execs can use every broker connection to a shared hotel and stall other guests | Yes | Pending (design: per-guest in-flight limit) | |
| B54 | The broker buffers up to 256 MiB per room request and had no idle timeout | Yes | Idle timeout fixed (B); body limits per route pending | B |
| B55 | Finished background execs, build contexts, guest room ids and latency samples are never pruned | Yes | Pending (weeks-scale) | |
| B56 | List, quota and usage asked hotels outside the guest's list | Yes | Fixed | B |
| B57 | Operator PATCH `hotels: []` or `max_rooms: 0` widened a guest | No | Fixed (400) | B |
| B58 | A build context cut short by a crash was used forever | Yes | Fixed | B |
| B59 | The room route passed `..` segments to the hotel | Yes | Fixed (400) | B |
| B60 | CI: `govulncheck` flags `crypto/x509` in Go 1.26.9 | No | Fixed in CI (1.26.10). The broker is built with Go 1.27.3 (clean). The release workflow still pins 1.26.9 | merge |
| B61 | The measured sealed image is not reproducible from source (unpinned apt) and packs the whole kit dir; rescue units are not masked | No | Pending | |

## Deploy plan

Each stage is a separate go. Stop at the first failed check.

1. **Merge** #310, then #311. No live effect.
2. **B: broker.** Build from the merge commit (Go 1.26.10 or later). Back up the
   binary and config. Swap, restart. Rooms keep running; ownership is rebuilt
   from labels. Check: guest path 200, one ops room create, exec and delete,
   a guest receipts page shows `"filtered": true` and `"scanned"`.
   Rollback: the old binary.
3. **H: shared hotels**, one at a time, least used first. Only when the hotel
   has no live rooms (`install.sh` now refuses otherwise). Run `install.sh`
   from the merge checkout. Check: egress `GET /rooms` shows `port_bound` for
   new rooms, probe passes, one ops room with `deny_all` and one allowlist.
   Rollback: re-run `install.sh` from the previous checkout.
4. **S: dedicated sealed hotel.** A rebuild is a new guest with a new
   measurement, so all its rooms end. Needs the customer told and a window.
   Publish the new expected measurement.
5. **T: client tool.** `verify_receipts.py` ships with the merge; customers
   fetch the new copy.

## Pending, by owner

Engineering design: B16, B21, B22, B24 phase 2, B40, B41, B42, B47, B53.
Small follow-ups: B7, B19, B26, B27, B30, B44, B45 hardening, B51, B54 body
limits, B55, B61, release workflow Go version.
