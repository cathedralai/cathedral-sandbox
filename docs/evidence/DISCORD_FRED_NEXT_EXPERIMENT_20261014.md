# Discord → Fred (pick next experiment)

@wallscaler Rootfs checks are on [#1449](https://github.com/bigailabs/polariscomputer/pull/1449#issuecomment-6162033739) — holding, no boot. Evidence still points at **virtio-net never probing** (builtin present, zero serial lines; nft empty; DHCP file didn’t fix TLS). Ready to run whichever you pick next:

**A)** one identity boot with host `restrict=on` removed (launcher-only; same image/measurement)  
**B)** image/kernel fix if you land a commit  
**C)** something else you want instrumented

Ping the choice on #1449 and I’ll execute.
