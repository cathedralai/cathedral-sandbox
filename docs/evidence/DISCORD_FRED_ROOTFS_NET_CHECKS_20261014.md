# Discord → Fred (rootfs net checks)

@wallscaler Offline checks on [#1449](https://github.com/bigailabs/polariscomputer/pull/1449): no reboot; guests stopped.

1) **No** `virtio_net.ko` file — but it **is** in `modules.builtin` (compiled in).  
2) `nftables.conf` = empty inet filter chains (no drops).  
3) Serial: `virtio_blk` probes; **zero** `virtio_net` / `eth0` / `enp` / renamed.  
Sky tee-box netdev **device line identical** to ours (`virtio-net-pci,…`); we only differ with `restrict=on` + hostfwd bind. Reads as probe/bind, not nft / DHCP name.
