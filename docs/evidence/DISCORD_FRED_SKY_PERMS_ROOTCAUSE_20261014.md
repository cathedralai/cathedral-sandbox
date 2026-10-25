# Discord → Fred (Sky root cause — mission path)

@wallscaler Sky’s netbisect is the real fault — and I re-checked `51a4a67b` rootfs: `80-dhcp.network` is **0600**, `/opt/cathedral` **0700**, customer units **0600**. That matches `networkd: Permission denied` → no lease → TLS never answers. Serial “no NIC lines” was a red herring (Sky’s working guests are quiet on serial too).

**Mission next:** skip another diagnostic boot unless you still want it. Land the umask/chmod fix on #1452 (configs 0644, dirs/exec 0755). I’ll rebuild same wrapper → you release 4 / grant 12 → identity + admission. Fences/logs/`netbisect-skyrocket` left intact.
