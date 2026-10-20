# Discord → Fred (boot6 serial + alive at admission)

@wallscaler Serial + liveness answers on [#1449](https://github.com/bigailabs/polariscomputer/pull/1449):

**Alive at 04:46:43?** Yes. Host qemu unit ran `04:40:39Z` → stop only `04:55:02Z` (~14m27s). At `04:44:44Z` pid 461133 was still LISTEN on `84.32.220.48:8444`. Serve had not exited.

**Serial after serve Started (identity redacted):** file froze at `04:41:35Z` ≈ T0. After `Started cathedral-customer-snp` it only hits multi-user/graphical — **no connection/TLS lines** through stop. So guest never saw the Railway SYN on serial; with host still listening that reads as path/filter before hostfwd, not guest TLS dropping an arrived connect. Throwaway listener still up for your Railway check.
