# Broker isolation baseline (live, before the isolation change) — 20261023T173448Z

Guest `const` on `https://live.cathedral.computer`. Each room deleted right after read. Purpose: record what the live broker answers today for the two weak claims (missing `network`, missing `sealed`), to compare after deploy of the `isolation` change.

## hotels
```json
{"hotels":[{"drain":false,"free_rooms":700,"id":"nc","labels":{},"name":"New Cherry","up":true},{"drain":false,"free_rooms":700,"id":"c46","labels":{},"name":"Cherry 46","up":true},{"drain":false,"free_rooms":300,"id":"c48","labels":{},"name":"Cherry 48","up":true},{"drain":false,"free_rooms":1000,"id":"nc-sealed","labels":{"sealed":"true"},"name":"nc-sealed (SEV-SNP)","up":true}]}

```

## A. create with NO network field and NO sealed field
```json
{"created_at":"2026-10-23T17:34:51.886620+00:00","env_keys":[],"expires_at":"2026-10-23T18:34:51.886620+00:00","guest":{"allowlist_fail_closed":false,"container_id":"5f5f56c4442aa50325133eb271fd69b89f47b9b0357b3b0d3bdd749bd7eeca3d","dind":false,"image":"alpine:3.20","network_enforced":true,"network_mode":"public","network_name":"room-sealed-net-0","network_switchable":true},"hotel":"nc-sealed","id":"nc-sealed.sbx_d6333879c9cb","idle_timeout_seconds":null,"image_id":"img_e588856a2ada","labels":{"broker_guest":"const","customer":"const","smoke":"iso-baseline-20261023T173448Z"},"metrics":{"cpu_seconds":0,"deleted_at":null,"disk_bytes":0,"memory_peak_bytes":0,"network_bytes":0,"started_at":"2026-10-23T17:34:51.886620+00:00"},"network":{"allow":[],"enforced_by":"hotel_egress","mode":"public","policy":{"allow":[],"mode":"internet"},"policy_sha256":"25b91f87fa1c77cc62b3894ca9e2a9b38219495ed305d88e7e6ea7829a271391"},"resources":{"disk_gib":10,"memory_gib":4,"vcpu":1},"runtime":"docker","snapshot_id":null,"state":"running","ttl_seconds":3600}

```

| field | value |
| --- | --- |
| hotel | `nc-sealed` |
| network.mode | `public` |
| runtime | `docker` |
| isolation present | `False` |

## B. create with sealed:false and NO network field
```json
{"created_at":"2026-10-23T17:34:53.815542+00:00","env_keys":[],"expires_at":"2026-10-23T18:34:53.815542+00:00","guest":{"allowlist_fail_closed":false,"container_id":"0119bc4c9e8eefb0617d9f4d5fa05b2f281e016cc5b559e000d5cb846c5473df","dind":false,"image":"alpine:3.20","network_enforced":true,"network_mode":"public","network_name":"room-c48-net-0","network_switchable":true},"hotel":"c48","id":"c48.sbx_c04d0ae5e9ee","idle_timeout_seconds":null,"image_id":"img_858eb21a6ba7","labels":{"broker_guest":"const","customer":"const","smoke":"iso-baseline-20261023T173448Z"},"metrics":{"cpu_seconds":0,"deleted_at":null,"disk_bytes":0,"memory_peak_bytes":0,"network_bytes":0,"started_at":"2026-10-23T17:34:53.815542+00:00"},"network":{"allow":[],"enforced_by":"hotel_egress","mode":"public","policy":{"allow":[],"mode":"internet"},"policy_sha256":"25b91f87fa1c77cc62b3894ca9e2a9b38219495ed305d88e7e6ea7829a271391"},"resources":{"disk_gib":10,"memory_gib":4,"vcpu":1},"runtime":"docker","snapshot_id":null,"state":"running","ttl_seconds":3600}

```

| field | value |
| --- | --- |
| hotel | `c48` |
| network.mode | `public` |
| runtime | `docker` |
| isolation present | `False` |

## cleanup
delete nc-sealed.sbx_d6333879c9cb -> 204
delete c48.sbx_c04d0ae5e9ee -> 204

## reading
Live broker (pre-change) still defaults a missing `network` to `internet` and answers no `isolation` object; sealed placement follows the guest default (`default_sealed=true` for const). After deploy of `broker/isolation.go` + compat default: A and B must show `network.mode=deny_all` and an `isolation` object with `hotel_sealed` true for A and false for B.
