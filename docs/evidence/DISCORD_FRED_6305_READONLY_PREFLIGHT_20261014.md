# Discord → Fred (6305cb5c read-only preflight)

@wallscaler Read-only preflight for PR [#1452](https://github.com/bigailabs/polariscomputer/pull/1452) @ **`6305cb5c`** is back. No Toby build/dispatch. Trust-map / observer / diagnostic boot not repeated.

**1. Baseline `mkosi.extra` manifest**
- Path: `/root/snp-launch/cathedral-staging-20261013/project-verity/mkosi.extra`
- Compact sorted JSON SHA256: **`2330d24e293d32ad4f9e65b9ce2753b4618f55f6997ecdb5fb5376a4cfb79d6d`**
- File count: 18 · excluded subtrees absent
- Matches prior attempt2 packet

**2. Installed build-tool hashes** (resolved; mkosi **26**; none absent)
| tool | resolved | sha256 |
| --- | --- | --- |
| python | `/usr/bin/python3.14` | `52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41` |
| mkosi | `/usr/bin/mkosi` | `8a671b36fef6b71ece78c54288b0d97b449b854c71b598b16340a125bf5e9a03` |
| systemd-run | `/usr/bin/systemd-run` | `03a68bafb0ebc0f5eff41cbdf3cbbdf126a3bb87e21140f9147bf78edce36d88` |
| systemctl | `/usr/bin/systemctl` | `6394f5e8df92878184de9d4dfb7ac242471cb09daf89d23be4e81ae17e9c03b2` |
| ip | `/usr/bin/ip` | `2829deca72cff655d6d1290646abb9cc829da2e2db615eec8bc0ccd283acf3a7` |
| losetup | `/usr/sbin/losetup` | `fe584e61a8255f65854064073ed55bda5c325a3bc9343a28183bbefdbb326ff2` |
| mke2fs | `/usr/sbin/mke2fs` | `e42e49656dfc308efeed86f9bfad7746fc22ad1d4a3b0d508b5dba7a4b9a904f` |
| blockdev | `/usr/sbin/blockdev` | `03126e10ddc85388cd315c6c365d330dcefa0dc3e6f191c22712afb29da339e0` |
| mount | `/usr/bin/mount` | `66a7104ffb87e469ee3aeb00baa8c73093d765a66242b1d2eb8d3e5c37dcc627` |
| umount | `/usr/bin/umount` | `8d160edce6166bcc29f5b7cb8b9cc7b66feb176d6149f597340885fff8db85e3` |

**3. Preservation fences (existing guests untouched)**
| name | pid | startticks | command_sha256 |
| --- | --- | --- | --- |
| snp-guest | 6712 | 46424 | `48ad40b4…e076` |
| tee-box-dev | 63141 | 4552067 | `1651c97e…79db` |
| tee-box-official | 73539 | 4620243 | `db06ce97…b0ac` |

Prior image stat fences (size/mtime_ns/inode/device) captured for the existing staging `images` / `images-rootfs` / `images-verity` set — same set as attempt2; full JSON in local evidence.

**Observed extra (not one of the three protected):** `cathedral-customer-6305` pid **431797** startticks **46558158** (already running when I measured). Also present under `/root/snp-launch/cathedral-customer-20261013/images-customer/` — **not** launched or built by me.

**4. Pilot workload budget — confirmed**
- profile v2 **`[1, 4096, 5120]`** + scratch **8192 MiB**
- = 1 vCPU / 4 GiB RAM / 5 GiB disk / 8 GiB scratch
- Build-profile only; not customer execution or hardware qualification
- Host capacity snapshot: MemAvailable ~36 GiB, free disk ~779 GiB (wrapper ≥12 GiB / ≥30 GiB OK)

**Holding**
- Local reviewed wrapper SHA matches your packet: **`c92b6d6f…849e`**
- Host control tree currently has a **different** installed script SHA `e2276a63…` and intent dispatcher **`backend-owner`** (not Toby); latest control `source_ref` was `159d652e`, attempt2 was `6305cb5c`
- I did **not** dispatch. Waiting on your **exact reviewed commit + Toby-only build approval** tied to the completed packet before any Toby build/qual → then I sign policy/checkpoint → grant after HTTPS
