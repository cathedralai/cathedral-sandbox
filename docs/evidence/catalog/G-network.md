# Catalog G: room network and egress (review round 6)

Artifact: cathedral-sandbox at 22e7824 (frozen copy /private/tmp/claude-501/r6).
Files: cathedral/sandbox_egress.py, room-kit/room_egress.py,
room-kit/lib/room-net.sh, room-kit/lib/net_plan.py,
room-kit/lib/net_capacity.py, the network parts of room-kit/install.sh,
room-kit/sealed/host-net.sh. Consumer traced: cathedral/sandbox_guest.py.

Enforcement is two layered firewalls plus a userspace daemon:
- room-net.sh (iptables, IPv4) owns coarse per-bridge rules: drop private/
  link-local dests, drop spoofed sources outside the bridge CIDR, NAT out,
  allow return traffic, block inbound to guests, drop guest-to-guest (nft
  bridge family). Runs in the room daemon's host netns (unsealed) or inside
  the SNP guest (sealed).
- room_egress.py (nftables ip + bridge family, DNS, SNI/HTTP proxy, control
  socket) owns per-room policy. Deny by default: a room IP in no set has no
  egress. nft room_forward priority -5 runs before iptables FORWARD (0).
- sandbox_egress.py (EgressClient) is the API-side client over the control
  socket.

The order a packet is evaluated (both layers hook forward): nft bridge
room_guard (prio -300) -> nft ip room_prerouting (nat, dstnat-5) ->
nft ip room_forward (filter -5) -> iptables FORWARD chain ROOM-* (0) ->
iptables nat POSTROUTING MASQUERADE.

---

## cathedral/sandbox_egress.py (API-side client, 94 lines)

### _UnixHTTPConnection (31-40)
- Purpose: http.client over AF_UNIX to the egress control socket.
- Trusts: socket path from env. Side effects: opens a unix socket.
- Invariant: path is the daemon's socket, reachable by the poolroom group.

### EgressClient.__init__ / from_env (43-51)
- from_env reads CATHEDRAL_ROOM_EGRESS_SOCKET; empty -> None (daemon off).
- Caller: DockerGuestProvider.__init__ (sandbox_guest.py:1002).

### EgressClient._call (53-71)
- Purpose: one HTTP request/response over the socket, JSON in/out.
- Trusts: daemon's status and JSON body. Side effects: network (unix).
- On OSError -> SandboxOpError("egress_unavailable", 503, retry_after=10).
- Hazard: a non-JSON or truncated body is swallowed to {} (line 69-70);
  a 200 with an empty/garbled body yields doc={} and then apply() raises
  "applied a different policy" (see below). Fail-closed, not silent-open.

### EgressClient.apply (73-86)
- Purpose: PUT /rooms/<cid> with {sandbox_id, policy}. Return daemon doc.
- Trusts: the daemon echoes the exact canonical policy. Guard at 84-85:
  if doc["policy"] != dict(policy) -> raise "applied a different policy"
  (503). This is the cross-check that the API's canonical form and the
  daemon's canonical form agree. See divergence note under room_egress.
- Callers: DockerGuestProvider._start (1326), _switch_policy (1686).
- Invariant assumed: equality of two independently-canonicalized policies.

### EgressClient.forget (88-94)
- Purpose: DELETE /rooms/<cid>. Best effort; swallows SandboxOpError.
- Callers: _start error path (1329), _retire (1760).

Hazards (sandbox_egress.py):
- No caller auth beyond unix-socket file mode; trusts whoever can open it.
- apply() equality check depends on byte-identical canonicalization in two
  code bases. Any drift makes every create/switch fail 503 (fail closed).

---

## room-kit/room_egress.py (daemon, 881 lines)

### canonical / policy_sha256 (74-79)
- Canonical JSON (sort_keys, no spaces, UTF-8), sha256. Mirrors
  sandbox_api.network_policy_sha256.

### classify (89-136)
- Purpose: one allowlist entry -> ("cidr"|"host"|"wild", value). Enforcement
  copy of sandbox_api.normalize_allow_entry.
- Trusts: a string <=255. Strips optional :80/:443 on a hostname; rejects
  other ports, IP:port, IPv6, private/host/reserved (shared _NON_PUBLIC_V4),
  bad labels, trailing-numeric TLD.
- Invariant: same accept set and same canonical string as the API (verified,
  see findings). Exception TYPE differs (ValueError vs SandboxContractError)
  but both reject the same inputs.

### Policy.parse / document / allows_name (139-182)
- parse: mode in {internet,deny_all,allowlist}; allow<=256; allowlist needs
  >=1 entry; builds hosts/wilds/nets; canon = sorted union; nets collapsed
  with ipaddress.collapse_addresses for the nft interval set only.
- document(): {mode, allow:list(canon)} (un-collapsed) -> matches API.
- allows_name: exact host match or endswith("."+wild). Lowercases, rstrips ".".
- Hazard: allows_name does not match a wildcard's own suffix (by design).

### Room dataclass (185-193): container_id, sandbox_id, ip, mac, port, policy.

### nft_name (198-199): table name pool_room_egress_<sanitized room id>.

### Rules (202-288)
- base(rooms) (218-263): renders the whole two-table transaction. ip table:
  sets rooms(interval, = room CIDRs), open, named, allow(ipv4.ipv4 interval);
  chain room_prerouting (nat, dstnat-5): saddr !@rooms return; @open return;
  (saddr.daddr)@allow return; tcp/udp dport53 redirect dns; @named tcp443 ->
  tls; @named tcp80 -> http. chain room_forward (filter -5): same first three
  returns then counter drop. bridge table: sets ports(ifname),
  bound(ifname.ipv4), bound_mac(ifname.ether); chain room_guard (prerouting
  -300): iif !@ports return; wrong MAC drop; wrong ip saddr drop; wrong arp
  saddr drop.
- elements(verb, room) (265-280): per-room set elements (open/named/allow and
  ports/bound/bound_mac). Trusts room.ip/mac/port are shell/nft-safe (ip/mac
  validated by facts(); port is a kernel ifname, json.dumps-quoted).
- install / change (282-288): run base, or an element delta.
- Side effects: runs `nft -f -` (30s). Raises RuntimeError on nonzero.
- Hazard: base() is deny-by-default; correctness of isolation rests entirely
  on this one script and on every room having a port (see Table.put).

### sh / Docker.facts / Docker.running (293-327)
- facts(cid) (304-324): docker inspect for (running, netns, ip, mac); then
  nsenter into the netns to read eth0@ifN, then host `ip -o link show` to map
  ifN -> host veth name (room.port). Trusts docker output; validates ip is
  IPv4. port None if any step fails.
- Side effects: runs docker, nsenter, ip. No lock.
- Invariant: the ifindex is globally unique on the host, so the veth match is
  exact. If port is None the room is refused by put (fail closed, B20).

### Table (332-447)
- State: by_ip, by_cid; one threading.Lock; on_change callback (proxy.recheck).
- load (342-364): read state.json; drop rooms whose container is not running;
  if docker.running() throws -> rooms=[] (all policies dropped); reinstall nft
  from survivors under lock.
- save (366-374): write state.json.tmp then os.replace (atomic rename). Called
  under lock in put/forget. File in /run/pool-room-egress (tmpfs, root:poolroom
  0750).
- put (376-407): facts(); refuse if no port; under lock, drop old record and
  any stale room on the same IP in the same transaction, add the new room,
  save. Then on_change(new) and flush_conntrack(ip) OUTSIDE the lock.
- forget (409-419): drop record, delete its elements, save; on_change with a
  synthetic deny_all room (closes proxy conns); flush_conntrack.
- _run (421-435): run an element delta; on RuntimeError reinstall the whole
  table from by_cid (source of truth) then re-apply the `add ` lines. Correct
  because dropped rooms are already popped from by_cid before _run and the new
  room is added after.
- policy_of (437-439): by_ip lookup.
- reconcile (441-447): forget rooms whose container is gone. Called every 15s.
- Hazards: load() on a docker blip wipes all policies to deny-by-default and
  nothing re-applies (API does not re-push on egress-only restart); reconcile
  only forgets, never re-adds.

### flush_conntrack (450-458): conntrack -D -s/-d ip. Best effort.

### DNS: dns_question (463-480), dns_reply (483-487), Resolver (493-539),
### DNSUDP (542-554), dns_tcp (557-571)
- dns_question: exactly one question; rejects compressed names (0xC0),
  name>270. Returns (qname lower, qtype, end).
- Resolver.decide (497-508): malformed -> b"" (drop). policy None or deny_all
  -> REFUSED. internet or allows_name -> None (forward). else NXDOMAIN.
  qtype is NOT consulted (AAAA for an allowed name forwards).
- Resolver.forward (510-533): try each upstream over UDP, 3s each; on all fail
  -> SERVFAIL. No TCP to upstream, no cache, no EDNS.
- Resolver.answer (535-539): local, or forward.
- dns_tcp: length-prefixed; 30s read timeout; serves answer() over TCP but
  forward() still goes upstream over UDP.
- Side effects: UDP sockets to upstream. Bound on the bridge gateway(s).
- Hazards: a TCP DNS client gets a UDP-sourced (possibly TC-truncated) answer
  with no TCP re-query; no cache; AAAA forwarded for allowed names.

### Proxy: tls_sni (576-601), read_client_hello (604-620),
### read_http_head (623-636), public_ipv4 (639-641), resolve_ipv4 (644-646),
### Proxy class (649-710), pipe (713-727)
- tls_sni: parse SNI from a ClientHello; any malformed -> None (try/except).
- read_client_hello: read TLS records (type 22) until the handshake is whole;
  ClientHello >65536 -> ValueError. A record with body length 0 does not grow
  hs: a stream of empty type-22 records loops until the outer 15s wait_for.
- read_http_head: readuntil(\r\n\r\n) (stream limit 65536); >32768 -> ValueError;
  first Host header; [ipv6] host -> None; strips :port.
- Proxy.handle (669-710): read name (15s cap); if no name / no policy / not
  allowed -> 403 (http) or close (tls). Resolve name via the HOST resolver
  (not the hotel resolver), keep only is_global addrs, connect to addrs[0].
  Register the conn in active[ip], re-check policy after registration (closes
  the switch race), then write the first bytes and pipe both ways.
- recheck (656-667): on a policy change, abort this room's conns the new policy
  disallows.
- Side effects: outbound TCP to upstream. active dict tracks conns per room IP.
- Invariants: proxy resolves and connects itself; the room never influences the
  destination except by the name it asked for; is_global blocks private answers.
- Hazards: NO per-room concurrent-connection cap (active grows unbounded);
  header read capped at 15s but a room can open many such connections; proxy
  resolution via host resolver only (is_global is the metadata guard, not
  _NON_PUBLIC_V4, so the two "public" definitions differ at the edges, e.g.
  192.0.2.0/24 is allowlistable but is_global-rejected: fail closed).

### Control (732-788), ControlServer (791-792)
- HTTP over the unix socket. do_GET /health,/rooms; do_PUT/do_DELETE
  /rooms/<[0-9a-f]{12,64}>. PUT body: Policy.parse(doc.policy); bad -> 400;
  apply failure -> 502. sandbox_id = str(doc.sandbox_id or "") UNVALIDATED.
- port_bound in the PUT reply is (room.port is not None); always true here
  because put() refuses a portless room.
- Auth: socket file mode only (root:poolroom 0660); no SO_PEERCRED, no token.

### read_env (797-804), room_networks (807-814), bound_socket (817-823),
### serve (826-842), main (845-877)
- room_networks: main bridge (ROOM_BRIDGE_CIDR) + each ROOM_NETS CIDR, gateway
  = network+1. bound_socket uses IP_FREEBIND (bridge may not exist yet).
- serve: bind DNS(UDP+TCP), http, tls on every gateway; 15s reconcile loop.
- main: load env, build Rules/Docker/Table/Proxy/Resolver, chown socket to the
  poolroom group, serve.
- Invariant: ROOM_DNS upstream defaults 1.1.1.1; gateways are trusted bind IPs.

Hazards (room_egress.py), consolidated:
- Admission window: a container is live on the bridge after `docker run`
  returns but before apply() puts it in @ports/@bound and the ip sets. During
  that window the bridge guard does not bind its port (iif !@ports return), so
  a raw-socket room can forge a same-bridge internet room's source IP and get
  blind egress under @open. See findings G1.
- No proxy connection cap; empty-TLS-record and header slowloris bounded to 15s
  each but multipliable. See findings G2.
- IPv6 is entirely outside both the ip nft table and iptables; the bridge guard
  has no ether-type-ip6 source bind; the resolver forwards AAAA for allowed
  names. See findings G3 (sharpens B45) and the exact disable site.
- DNS: no TCP-upstream fallback, no cache, TC never set locally. G4.
- Control socket: group-only auth, unvalidated sandbox_id. Low.

---

## room-kit/lib/room-net.sh (106 lines)

### down (29-44)
- Delete every rule tagged pool-room:<id> in filter+nat; flush/delete CHAIN,
  CHAIN-IN; delete the nft bridge table; delete the main bridge and any
  rmnetN bridges.
- Trusts: the tag comment to find its own rules. Side effects: iptables, nft,
  ip link.

### up (46-71)
- down first; refuse if the room CIDR is already routed on the host; delete
  dockerd's local-kv.db so a changed CIDR takes effect; create the bridge,
  address, up; ip_forward=1; create CHAIN, CHAIN-IN (conntrack
  RELATED,ESTABLISHED accept then DROP); nft bridge table + forward chain;
  guard(main); for each ROOM_NETS: refuse if routed, else guard(rmnetN);
  finally insert `FORWARD 1 -j CHAIN`.
- Trusts: ROOM_ID, ROOM_BRIDGE, ROOM_BRIDGE_CIDR, ROOM_NETS from room.env.
- Hazard: if `up` fails midway under set -e (e.g. a guard step), FORWARD may be
  left without the catch-all jump (the final -I FORWARD is last); ExecStartPre
  failure then blocks the room daemon (fail closed). B35 covers the auto-mode
  re-install variant.

### guard (75-99)
- Per bridge: drop link-local+private dests (169.254/16,10/8,172.16/12,
  192.168/16,100.64/10); drop sources outside the bridge CIDR (net-raw
  anti-spoof); accept egress leaving the bridge; accept established return;
  drop new inbound to guests; drop everything else from the bridge; allow the
  egress daemon ports (DNS udp, DNS/http/tls tcp) in CHAIN-IN; MASQUERADE the
  bridge CIDR; nft bridge `meta ibrname <br> drop` (guest-to-guest, all ether
  types).
- Trusts: the bridge name and CIDR. Invariant: the anti-spoof `! -s $net`
  only constrains to the bridge CIDR, not to the per-room IP (that is the nft
  bridge guard's job, and only for bound ports).
- Hazard: IPv4 only; no net.ipv6.conf.<br>.disable_ipv6 and no ip6tables drop.
  This is the single cleanest place to disable IPv6 per bridge (findings G3).

### status (104): prints the bridge, rmnet bridges, both chains, the MASQUERADE
rule and the nft bridge table.

---

## room-kit/lib/net_plan.py (64 lines)

### block_prefix (24-29): smallest prefix whose block holds `size` usable
guests (2^(32-p) - 3 >= size). size 1000 -> /22, 1023 -> /21.

### plan (32-49): size clamped [1,1023]; if port_cap<=0 or slots<=port_cap ->
([],None) (main bridge holds all); want=ceil(slots/size); carve `prefix`
blocks from the pool, skipping any that overlap a routed CIDR; return up to
`want`. If the pool runs out, return the blocks that fit plus a warning
string (install uses the partial list; stderr warning only).
- Trusts: slots/port_cap/size ints, pool CIDR, routed CIDRs from `ip route`.
- Invariant: install.sh passes ROOM_BRIDGE_CIDR in `routed`, so the plan never
  reuses the main bridge subnet. Raises if one network is larger than the pool.
- Hazard: partial plan under-provisions silently vs the machine's resource
  slots; net_capacity is then computed over the smaller list, so slots and
  networks stay consistent (fewer rooms than possible). Low.

### main (52-60): CLI; prints the space-separated CIDRs; warning to stderr;
exit 0 even when the pool is exhausted.

---

## room-kit/lib/net_capacity.py (18 lines)
- CLI: with ROOM_NETS, sum(min(size, net_addrs-3)) over the nets (size clamped
  1..1023); without, min(bridge_addrs-3, port_cap) or bridge_addrs-3 if cap<=0.
- Trusts: argv CIDRs. Invariant: -3 for network/gateway/broadcast matches
  block_prefix. Used by install.sh step 8 to size the host.
- Hazard: no argv -> IndexError (operator misuse only).

---

## room-kit/install.sh (network parts)

### refuse_restart_with_rooms (34-49): refuse an update while labelled rooms
are live unless ROOM_RESTART_WITH_ROOMS=1; if the room daemon socket does not
answer, exit 1 (B24 phase 1, B34).

### room.env resolution (92-118): writes the resolved room.env; in auto mode,
until step 8 plans the list, keeps the previously-applied ROOM_NETS so a re-run
that fails before step 8 leaves no live room network without egress rules (B35).

### daemon.json (183-216): room dockerd with iptables=false, ip6tables=false,
ip-masq=false, userland-proxy=false, bridge=$ROOM_BRIDGE, default-runtime runsc.
So the room daemon never writes host firewall rules; room-net.sh owns them.
- Hazard: ip6tables=false means the room daemon also does not manage IPv6; with
  no explicit disable, kernel link-local IPv6 remains on bridges/veths (B45).

### room-net ExecStartPre/StopPost (226-228): the docker unit runs room-net.sh
up before dockerd and down after. egress unit (376-397) is PartOf the docker
unit and Before the API, so fenced rooms get DNS+proxy before they run.

### step 8 auto plan (256-270): size unbridged; collect routed CIDRs from
`ip route` excluding this room's own bridges; net_plan; net_capacity; size.

### sysctl: net.ipv4.ip_forward=1 (room-net.sh up). No IPv6 sysctl anywhere.

Hazards (install.sh network):
- No IPv6 disable; see G3.
- Auto-mode partial plan under-provisions; see net_plan.

---

## room-kit/sealed/host-net.sh (45 lines)
- Host side of the SNP guest tap: /30 on the tap, drop private dests from the
  guest, accept only the guest IP as source, drop else, accept established
  return, drop new inbound, MASQUERADE the guest /32. Own chains SEALED-*-FWD/
  -IN. IPv4 only.
- Trusts: SEALED_TAP, SEALED_HOST_IP, SEALED_GUEST_IP from sealed.env.
- Note: `-d "$PRIVATE"` is a comma-joined list; iptables expands a comma list
  into one rule per address (verified as a documented iptables feature; sealed
  hotels are in production, so it resolves). Not a bug.
- Invariant: nothing host-side can open a connection into the guest; only the
  broker reaches the hotel API port (enforced by the tap being point-to-point
  and the IN chain dropping new inbound).
- Hazard: IPv4 only (the guest link has no IPv6; the guest's own room-net.sh
  inside the SNP guest has the same IPv6 gap, G3).

---

## Rule set per mode, as the daemon renders it

For room IP R on bridge with CIDR set @rooms, ports set @ports (host veth of R),
bound {veth.R}, bound_mac {veth.MAC}. Evaluation order for a frame from R:

1. nft bridge room_guard (prio -300): if iif not a known room port -> return
   (NO bind check). Else: wrong source MAC -> drop; IPv4 wrong source IP ->
   drop; ARP wrong sender IP -> drop. (No IPv6 arm.)
2. nft ip room_prerouting (nat dstnat-5): saddr !@rooms return; saddr @open
   return; (saddr.daddr)@allow return; tcp/udp dport53 redirect :15353;
   @named tcp443 redirect :15443; @named tcp80 redirect :15080.
3. nft ip room_forward (filter -5): saddr !@rooms return; saddr @open return;
   (saddr.daddr)@allow return; counter drop.
4. iptables FORWARD -> ROOM-<id>: -d private -j DROP (x5); ! -s cidr -j DROP;
   ! -o br -j ACCEPT; (-o br established ACCEPT; -o br DROP; -i br DROP).
5. iptables nat POSTROUTING: -s cidr ! -o br -j MASQUERADE.

- internet: R in @open. prerouting @open return (no redirect); forward @open
  return; iptables allows public egress, drops private. DNS/80/443 NOT
  redirected -> the room uses real DNS and direct connections.
- deny_all: R in no ip set. prerouting: only dport53 redirect matches (DNS goes
  to the resolver, which REFUSES). forward: counter drop. No egress.
- allowlist: R in @named iff it has hostnames; (R.cidr) pairs in @allow for
  each CIDR/addr entry. prerouting: @allow pairs return (all ports direct);
  dport53 -> resolver (NXDOMAIN except allowed names); @named tcp80/443 ->
  proxy. forward: @allow pairs return; everything else counter drop (so a
  named host on a non-80/443 port is dropped).

Per-destination trace (allowlist room with one hostname + one CIDR):
- TCP 443 to a public IP not in @allow: prerouting @named tcp443 -> proxy;
  proxy reads SNI; if the SNI is an allowed name it reaches the name's own
  resolved address, else closes. A raw IP with no SNI -> closed.
- UDP 53 to 8.8.8.8: redirected to the resolver; allowed name -> forwarded,
  else NXDOMAIN.
- UDP 53 to the daemon (gateway): CHAIN-IN accepts the DNS port; same resolver.
- TCP 80 to another room: dest is a same-bridge room IP; nft bridge
  `meta ibrname drop` (room-net.sh) drops guest-to-guest; also private-range
  not relevant (same /22 is the bridge CIDR, allowed as dest by iptables, but
  the L2 drop fires first). Cross-bridge room: ! -s / routing + forward drop.
- ICMP to the gateway: CHAIN-IN has no ICMP accept -> dropped (only DNS/proxy
  ports open inbound). Egress ICMP to public: forward counter drop (not in any
  allow set).
- TCP to the host bridge IP on the API port: the API listens on 127.0.0.1
  only; the bridge gateway IP is the daemon's DNS/proxy, not the API. A guest
  cannot reach 127.0.0.1 of the host. CHAIN-IN drops non-DNS/proxy ports.
- TCP to 169.254.169.254 (metadata): iptables -d 169.254.0.0/16 DROP; also not
  in any allow set. Dropped twice.
- forged source IP: bound port -> nft bridge `ip saddr != @bound drop`.
  UNBOUND port (admission window) -> not dropped at L2; may hit @open if it
  forges a same-bridge internet room's IP (G1).
- forged source MAC: nft bridge `ether saddr != @bound_mac drop` (any ether
  type) for bound ports. Unbound port: not checked.
- ARP for another room's IP: nft bridge `arp saddr ip != @bound drop` for
  bound ports; guest-to-guest ibrname drop also blocks the reply.
- fragments: no explicit handling; nft/iptables match on L3/L4 of each
  fragment; conntrack reassembles for the ESTABLISHED match. No specific
  anti-fragmentation rule. Public egress fragments from an allowed flow pass;
  no observed bypass (set membership is on saddr/daddr, present in every
  fragment's IP header).
- IPv6: no ip6 table, no ip6tables, no bridge ip6 source bind. Covered only by
  the MAC bind (bound ports) and the ibrname guest-to-guest drop. Not reachable
  today (gVisor guests have no v6, bridges have no v6 route), but unenforced if
  ever enabled. Disable site: room-net.sh guard() per bridge.
