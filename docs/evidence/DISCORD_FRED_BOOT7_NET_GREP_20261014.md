# Discord → Fred (boot7 net grep + guest stopped)

@wallscaler Serial + sky `.network` on [#1449](https://github.com/bigailabs/polariscomputer/pull/1449): boot7 has **no DHCP / 10.0.2 / carrier** lines; networkd + network-online still came up; nftables Finished OK. **Sky base yes** — `80-dhcp.network` (`Name=en*` / `DHCP=yes`). **Customer profile / 20edf69d no** — no `.network` in mkosi.extra or source tar. Guest stopped; fences intact. Your call on the ~90 min image fix tonight (grant → 06:37) vs hold.
