# Review round 6 catalogs (2026-10-23)

Function-by-function reading notes from the round 6 readers, one file per
reader. They are the working material behind `../REVIEW_ROUNDS_2026-10-23.md`:
what each function does, the invariants it relies on, and the candidates each
reader raised before verification. A candidate here is not a finding; the
findings table is the source of truth.

| File | Scope |
|---|---|
| A-broker-main.md | broker/main.go: routes, create, placement, sync loop, state |
| B-broker-compat.md | broker/compat.go, build.go: the client (Harbor, ctcli) path |
| C-broker-core.md | broker/hotels.go, guests.go, probe.go, images.go, state.go |
| D-hotel-server.md | cathedral/sandbox_server.py: the hotel HTTP layer |
| E-api-provider.md | cathedral/sandbox_api.py, sandbox_provider.py: contracts and the in-memory provider |
| F-docker-guest.md | cathedral/sandbox_guest.py: rooms on the Docker daemon |
| G-network.md | room-kit/room_egress.py, lib/room-net.sh: policy enforcement outside the room |
| I-installer.md | room-kit/install.sh, profiles, room_health.py, assess.py, size.py |
| J-sealed.md | room-kit/sealed: build, launch, host network, install |
| K-affine-lane.md | cathedral/affline_rerun.py, affine_claim.py, affine_validator.py (dormant lane) |
| L-cli-serve.md | cathedral/cli.py serve path, sandbox_runtime.py, key store and quota |
| M-sn94-miner.md | SN94 miner units, updater, bundle |
| N-docs-vs-code.md | customer and operator docs against the fixed code |
| O-mutation.md | every fix hunk of #312 reverted alone: which tests caught it |
| P-python-gaps.md | the Python test guards added after O |
| Q-go-gaps.md | the broker test guards added after O, with the create-behind-execs measurement |
| R-installer-behaviour.md | install.sh, room-net.sh, host-net.sh and install-sealed.sh step 5 run on a fake host: what the harness fakes, what each property proves, B150 and B151 |

Reader H (receipts) folded its notes into the findings table directly.
