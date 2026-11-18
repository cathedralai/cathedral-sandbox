# AB#758: Omarchy / Hyprland sandbox feasibility

Status: evaluation only. No Omarchy or Hyprland customer template is approved.
This brief does not change the existing Desktop template (AB#573).

## Current boundary and decision

The sealed room Docker daemon defaults to gVisor `runsc`
(`room-kit/install.sh:200-235`), the `/v1` sandbox profile uses that daemon
(`room-kit/profiles/v1.sh:8-9`), and the TEE box configuration requires `runsc`
(`cathedral/tee_box/configure.py:311-312`). These facts establish the runtime
boundary, not Hyprland compatibility. The existing Xvfb/Openbox Desktop proof
does not exercise Wayland, Hyprland rendering, or remote Wayland input.

Hyprland documents a headless output and a separate remote display server for
access and interaction. Its virtual-GPU guide describes GPU and Virtio-GPU
routes; gVisor documents GPU support through specific `runsc` flags and driver
capabilities. None of those routes is enabled or proven by the current room
installer. In particular, the presence of a `/dev/dri` node on a host says
nothing about its availability or safe use inside a customer sandbox.

**Recommendation:** do not list an Omarchy / Hyprland template yet. First
try a pinned, nonproduction software-rendered image in the existing `runsc`
room. If it cannot boot, render, accept input, reconnect, and clean up there,
write down the exact failing syscall/device or display step. A different GPU
or VM lane needs a separate isolation and trust review, not a silent change to
the sealed tier. Omarchy's full image contents and distribution rights are a
separate approval from proving the Hyprland compositor.

Sources:

- [Hyprland headless display and remote server](https://wiki.hypr.land/configuring/extra/virtual-gpu/)
- [Hyprland headless output command](https://wiki.hypr.land/configuring/core/advanced-configuration/using-hyprctl/)
- [gVisor GPU support and driver capabilities](https://gvisor.dev/docs/user_guide/gpu/)

## First pilot: existing sealed runtime

Use an approved nonproduction hotel and internal test account. Pin the guest
image by digest; record the room-kit, broker, `runsc`, Hyprland, remote server,
and image versions. Do not expose new devices or grant privileges for this
first pass. On the host and inside the resulting sandbox, capture separately:

```sh
uname -m
uname -r
id
ls -l /dev/dri /dev/input 2>&1 || true
command -v Hyprland || true
command -v hyprctl || true
command -v wayvnc || true
```

The probe inventories devices and binaries; it is not a compatibility test.
The actual trial must record the compositor's startup output and exit status,
its named headless output, one visible frame, a pointer and keyboard input
response, disconnect/reconnect without losing the session, and a terminal
command in the same sandbox. Record which remote server carried display and
input, its authentication boundary, and whether the edge or API saw frame
plaintext. If a software renderer is used, measure CPU/RAM and frame rate
before deciding it can support an interactive customer session.

## Release gates

1. Publish a reproducible image build and immutable digest. Resolve Omarchy
   package, font, theme and image redistribution rights before calling it an
   Omarchy template.
2. Prove create, ready, browser/terminal interaction, remote display/input,
   reconnect, stop, delete, and no surviving session or input channel. Repeat
   the cleanup test after a failed start and an interrupted client connection.
3. Measure cold and warm startup, CPU, RAM, disk, network and concurrency on
   the chosen host. State the price unit and persistence limits from the actual
   product contract, not from the existing Openbox Desktop numbers.
4. Check tenant separation, display authentication, network policy and
   confidentiality against the chosen runtime. A GPU or direct-VM pilot gets
   its own trust label and security review before it can be offered to a
   customer; do not inherit an AMD SEV-SNP claim from the current tier.
5. Obtain an independent review, green CI for any implementation, and a live
   staging or production lifecycle record before adding a catalog entry or
   moving AB#758 to Done.

**Next input:** engineering names a nonproduction eligible hotel and approves
the first no-new-privilege trial. If that fails, engineering decides whether a
separate isolated GPU/VM route is worth its host, cost and trust review, or
records a no-go. No customer claim or host change follows from this document.
