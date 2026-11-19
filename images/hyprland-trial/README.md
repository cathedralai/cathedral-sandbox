# AB#758 internal Hyprland trial

This image probes the compositor only. It contains no Omarchy distribution, no
credentials, no customer template entry, and no device or privilege request.
The entrypoint is a sleeping unprivileged user so the normal sealed room create
path can launch it. The image is useful only after its CI build publishes a
digest and an operator confirms the trial hotel's safety gate.

## Gate

Use `nc-sealed-3` only. Before creating a room, the operator confirms the hotel
is up, drained, and has zero customer rooms. Use an internal tester account and
the published `ghcr.io/cathedralai/hyprland-trial@sha256:<digest>` reference.
Do not add devices, privileges, host networking, or a customer catalog entry.
If the hotel cannot meet that gate, record a blocked trial on AB#758.

## Probe

Run `/usr/local/bin/hyprland-trial-probe /tmp/hyprland-evidence` with the
room's normal exec route and collect the evidence directory through the
approved room file route. The script:

1. Starts Hyprland and records its log and version. Missing Wayland socket or
   `HEADLESS` output is a no-go.
2. Binds WayVNC to `127.0.0.1:5900` inside the room. It captures one frame.
3. Starts a native Wayland terminal, moves and clicks the pointer, types a
   sentinel and checks that the terminal received it.
4. Reconnects a new VNC client and captures a second frame.
5. Records CPU and RSS for the compositor, VNC server and terminal, then stops
   its own processes. A failed phase keeps its logs and exits nonzero.

The operator also records room/image digest, hotel/runtime version, receipt
IDs and verification, room cleanup and final hotel occupancy. A script PASS
alone is insufficient for AB#758 Done. A visual inspection of the captured
frame must show a rendered terminal, and a longer reconnect/cleanup trial is
needed before any customer catalog decision.
