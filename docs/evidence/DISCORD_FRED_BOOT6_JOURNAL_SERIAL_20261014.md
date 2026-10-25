# Discord → Fred (boot6 serial + journal; no boot yet)

@wallscaler Path check ack (Railway 50ms/200). Listener still up — no kill/boot yet.

Serial from T0→exit: **empty after `04:41:35Z`**. After serve Started only multi-user/graphical; no crash/TLS lines. `qemu.log` 0B.

`journalctl -n 15` on [#1449](https://github.com/bigailabs/polariscomputer/pull/1449): boot6 did **not** timeout — `Deactivated successfully` at Toby’s `04:55` abort stop. Pid was still LISTEN at `04:44` and `04:54`; my earlier “gone before 960s” was a bad `ps` false negative, not a crash. So guest was up and just not answering HTTPS when Railway tried. Holding for your next instrumented drill.
