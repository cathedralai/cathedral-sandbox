# Discord → Fred (boot7 Outcome A)

@wallscaler Boot7 drill done — **Outcome A**. TCP connected (~50ms), TLS hung 30s (`start_tls` ConnectTimeout). Host `ss` showed `ESTAB` owned by qemu (Recv-Q≈517 → CLOSE-WAIT) — QEMU accepted, guest never read/handshaked. Details on [#1449](https://github.com/bigailabs/polariscomputer/pull/1449#issuecomment-6161506467). Guest left up for socket preserve; say when to stop. Next step is guest-side / image, not host user-net.
