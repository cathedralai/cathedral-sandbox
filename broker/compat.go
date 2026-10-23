// Compatibility layer for the published Cathedral clients (the Harbor plugin
// and ctcli). They speak the Cathedral cloud API, not the hotel /v1 API.
// A request is a client request when its User-Agent starts with one of
// compatAgents. Native /v1 callers are not affected.
//
// What the layer does:
//   - Answers routes the hotels do not have: account, catalog, image import,
//     background execs (/execs), run reports.
//   - Translates create, exec, lifetime and file-mode fields.
//   - Gives each room a UUID id (ctcli accepts only UUIDs).
//   - Moves files with exec + base64, because the hotel files and tar routes
//     reach only the room's /work volume, not its root file system.
//   - Puts errors in the client envelope {"detail": {"error": code, ...}}.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

var compatAgents = []string{"cathedral-harbor/", "ctcli/"}

const (
	defaultMaxExecSeconds = 14400    // Harbor asks for up to 4 hours; the hotels allow it by default
	fileMaxBytes          = 64 << 20 // file and tar moves through exec, base64 encoded
)

func isCompat(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")
	for _, p := range compatAgents {
		if strings.HasPrefix(ua, p) {
			return true
		}
	}
	return false
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

type compatImage struct {
	ID        string
	Ref       string
	CPU       float64
	MemoryGiB float64
	DiskGiB   float64
	// A built image (build.go): the Dockerfile, the context and the build
	// state on each hotel. The context is kept in state_dir, not in the state file.
	Build      bool
	Dockerfile string
	buildCtx   []byte
	ctxMissing bool
	builds     map[string]*buildHotel
	failedAt   map[string]time.Time
}

type compatExec struct {
	ID     string
	room   string // uuid
	done   chan struct{}
	cancel context.CancelFunc
	result map[string]any
	state  string
	doneAt time.Time // when the command ended; a finished result is kept one hour
}

// execKeep is how long a finished background exec result stays for polling.
const execKeep = time.Hour

type compatTomb struct {
	bid string
	at  time.Time
}

type compatState struct {
	mu     sync.Mutex
	images map[string]*compatImage // image_id -> image
	idem   map[string]*idemEntry   // guest + Idempotency-Key -> answer
	execs  map[string]*compatExec  // exec_id -> exec
	tombs  map[string]compatTomb   // uuid -> deleted room
}

type idemEntry struct {
	done   chan struct{}
	status int
	body   []byte
	at     time.Time
}

func newCompat() *compatState {
	return &compatState{images: map[string]*compatImage{}, idem: map[string]*idemEntry{}, execs: map[string]*compatExec{}, tombs: map[string]compatTomb{}}
}

// compatErr writes an error in both envelopes: the hotel one and the client one.
func compatErr(w http.ResponseWriter, status int, code, msg string, retryAfter int) {
	detail := map[string]any{"error": code, "message": msg}
	if retryAfter > 0 {
		detail["retry_after_s"] = retryAfter
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	writeJSON(w, status, map[string]any{"detail": detail})
}

// reEnvelope turns a hotel or broker error body into the client envelope.
func reEnvelope(status int, hdr http.Header, body []byte) []byte {
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return body
	}
	code, msg := "", ""
	switch e := doc["error"].(type) {
	case map[string]any:
		code, _ = e["code"].(string)
		msg, _ = e["message"].(string)
	case string:
		code = e
	}
	if code == "" {
		return body
	}
	detail := map[string]any{"error": code, "message": msg}
	if ra, err := strconv.Atoi(hdr.Get("Retry-After")); err == nil && ra > 0 {
		detail["retry_after_s"] = ra
	}
	out, _ := json.Marshal(map[string]any{"detail": detail})
	return out
}

// capture records a handler's answer so the layer can rewrite it.
type capture struct {
	hdr    http.Header
	status int
	buf    bytes.Buffer
}

func (c *capture) Header() http.Header         { return c.hdr }
func (c *capture) WriteHeader(s int)           { c.status = s }
func (c *capture) Write(p []byte) (int, error) { return c.buf.Write(p) }

func (b *broker) roomByUUID(g *guestState, id string) *room {
	b.mu.Lock()
	defer b.mu.Unlock()
	rm := b.byUUID[id]
	if rm == nil || rm.guest != g.cfg.ID {
		return nil
	}
	return rm
}

// hotelExec runs one exec on a room's hotel and returns the hotel answer.
func (b *broker) hotelExec(ctx context.Context, rm *room, body map[string]any, timeout int) (int, map[string]any, error) {
	if max := b.maxExec(); timeout <= 0 || timeout > max {
		timeout = max
	}
	body["timeout_seconds"] = timeout
	raw, _ := json.Marshal(body)
	status, _, out, err := rm.h.do(ctx, "POST", "/v1/sandboxes/"+url.PathEscape(rm.hid)+"/exec", nil, raw, time.Duration(timeout+60)*time.Second)
	if err != nil {
		return 0, nil, err
	}
	var doc map[string]any
	_ = json.Unmarshal(out, &doc)
	return status, doc, nil
}

func (b *broker) serveCompat(w http.ResponseWriter, r *http.Request, g *guestState) {
	p := r.URL.Path
	switch {
	case p == "/v1/account" && r.Method == "GET":
		writeJSON(w, 200, map[string]any{"owner_id": g.cfg.ID, "email": "", "scopes": []string{"sandboxes:control"},
			"teams": []any{}, "api_key": map[string]any{"expires_at": nil, "budget_usd": nil}})
	case p == "/v1/sandboxes/catalog" && r.Method == "GET":
		b.compatCatalog(w, g)
	case p == "/v1/runs" && r.Method == "POST":
		writeJSON(w, 201, map[string]any{"url": ""})
	case p == "/v1/images/import" && r.Method == "POST":
		b.compatImport(w, r, g)
	case p == "/v1/images/build" && r.Method == "POST":
		b.compatBuild(w, r, g)
	case strings.HasPrefix(p, "/v1/images/") && r.Method == "GET":
		id := strings.TrimPrefix(p, "/v1/images/")
		b.compat.mu.Lock()
		img := b.compat.images[id]
		b.compat.mu.Unlock()
		if img == nil {
			compatErr(w, 404, "image_not_found", "no image "+id, 0)
			return
		}
		if img.Build {
			b.ensureBuilds(img, g)
		}
		writeJSON(w, 200, b.imageView(img, g))
	case p == "/v1/sandboxes" && r.Method == "POST":
		b.compatIdem(w, r, g, func(w http.ResponseWriter, body []byte) { b.compatCreate(w, r, g, body) })
	case p == "/v1/sandboxes" && r.Method == "GET":
		b.compatList(w, r, g)
	case p == "/v1/quota" && r.Method == "GET":
		b.compatQuota(w, r, g)
	case p == "/v1/usage" && r.Method == "GET":
		c := &capture{hdr: http.Header{}, status: 200}
		b.handleUsage(c, r, g)
		var doc map[string]any
		_ = json.Unmarshal(c.buf.Bytes(), &doc)
		writeJSON(w, 200, map[string]any{"as_of": time.Now().UTC().Format(time.RFC3339), "groups": []any{}, "hotels": doc["hotels"]})
	case strings.HasPrefix(p, "/v1/sandboxes/"):
		b.compatRoom(w, r, g, strings.TrimPrefix(p, "/v1/sandboxes/"))
	default:
		c := &capture{hdr: http.Header{}, status: 200}
		b.serveNative(c, r, g)
		b.flushCompat(w, c, nil)
	}
}

// compatTemplates are the catalog templates: name -> {vcpu, memory GiB}.
var compatTemplates = map[string][2]int{"room-1x4": {1, 4}, "room-2x8": {2, 8}, "room-4x16": {4, 16}}

func (b *broker) compatCatalog(w http.ResponseWriter, g *guestState) {
	free := b.freeRoomsFor(g)
	tpl := func(name string, cpu, mem int, rate string) map[string]any {
		return map[string]any{"name": name, "resources": map[string]any{"cpu": cpu, "memory_gib": mem}, "hourly_rate_usd": rate,
			"network_modes": []string{"internet", "deny_all", "allowlist"}}
	}
	writeJSON(w, 200, map[string]any{
		// Each hotel enforces the room policy outside the room (nftables,
		// a hotel DNS resolver and an SNI/HTTP egress proxy) and can switch
		// it live: PUT /v1/sandboxes/{id}/network.
		"dynamic_network_policy": true,
		"network_allowlist": map[string]any{"hostnames": true, "wildcard_hostnames": true, "ipv4_addresses": true,
			"ipv4_cidrs": true, "ipv6": false, "hostname_ports": []int{80, 443}},
		"available": free > 0, "free_rooms": free, "max_lifetime_seconds": 23 * 3600, "cleanup_margin_seconds": 0,
		"exec_output_limit_bytes": 16 << 20, "max_exec_seconds": b.maxExec(),
		"templates": []any{tpl("room-1x4", 1, 4, "0.05"), tpl("room-2x8", 2, 8, "0.10"), tpl("room-4x16", 4, 16, "0.20")},
	})
}

func (b *broker) compatImport(w http.ResponseWriter, r *http.Request, g *guestState) {
	var req struct {
		Image     string         `json:"image"`
		Resources map[string]any `json:"resources"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if json.Unmarshal(raw, &req) != nil || req.Image == "" {
		compatErr(w, 400, "invalid_image", "image is required", 0)
		return
	}
	num := func(k string, d float64) float64 {
		if v, ok := req.Resources[k].(float64); ok && v > 0 {
			return v
		}
		return d
	}
	img := &compatImage{Ref: req.Image, CPU: num("cpu", 1), MemoryGiB: num("memory_gib", 4), DiskGiB: num("minimum_free_disk_gib", 10)}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%v|%v|%v", g.cfg.ID, img.Ref, img.CPU, img.MemoryGiB, img.DiskGiB)))
	h := hex.EncodeToString(sum[:16])
	img.ID = h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	b.compat.mu.Lock()
	b.compat.images[img.ID] = img
	b.compat.mu.Unlock()
	b.markDirty()
	// Warm every hotel in the background; a create pulls a missing image anyway.
	pf, _ := json.Marshal(map[string]any{"images": []string{img.Ref}})
	for _, ht := range b.hotelList() {
		if !g.limitsAllow(b, ht.cfg.ID) { // never touch a hotel outside the guest's list
			continue
		}
		go func(ht *hotel) {
			_, _, _, _ = ht.do(context.Background(), "POST", "/v1/images/prefetch", nil, pf, 10*time.Minute)
		}(ht)
	}
	writeJSON(w, 200, map[string]any{"image_id": img.ID, "state": "ready", "image": img.Ref})
}

// compatIdem runs fn at most once per guest + Idempotency-Key and replays its answer.
func (b *broker) compatIdem(w http.ResponseWriter, r *http.Request, g *guestState, fn func(http.ResponseWriter, []byte)) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fn(w, body)
		return
	}
	k := g.cfg.ID + "|" + r.URL.Path + "|" + key
	b.compat.mu.Lock()
	e := b.compat.idem[k]
	if e == nil {
		e = &idemEntry{done: make(chan struct{}), at: time.Now()}
		b.compat.idem[k] = e
		b.compat.mu.Unlock()
		c := &capture{hdr: http.Header{}, status: 200}
		fn(c, body)
		e.status, e.body = c.status, c.buf.Bytes()
		if c.status == 429 || c.status >= 500 || c.hdr.Get("Retry-After") != "" { // a retry may run it again
			b.compat.mu.Lock()
			delete(b.compat.idem, k)
			b.compat.mu.Unlock()
		}
		close(e.done)
		b.markDirty()
		for kk, v := range c.hdr {
			w.Header()[kk] = v
		}
	} else {
		b.compat.mu.Unlock()
		select {
		case <-e.done:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(e.status)
	_, _ = w.Write(e.body)
}

func (b *broker) compatCreate(w http.ResponseWriter, r *http.Request, g *guestState, raw []byte) {
	var req map[string]any
	if json.Unmarshal(raw, &req) != nil {
		compatErr(w, 400, "invalid_json", "request body is not JSON", 0)
		return
	}
	native := map[string]any{"labels": req["labels"]}
	res := map[string]any{"vcpu": 1, "memory_gib": 4, "disk_gib": 10}
	var pl placement
	if id, _ := req["image_id"].(string); id != "" {
		b.compat.mu.Lock()
		img := b.compat.images[id]
		ref := ""
		if img != nil && img.Build {
			// A built image is only on the hotels that built it.
			pl.images, ref = img.builtOn()
		} else if img != nil {
			ref = img.Ref
		}
		b.compat.mu.Unlock()
		if img == nil {
			compatErr(w, 404, "image_not_found", "no image "+id+"; import it first", 0)
			return
		}
		if ref == "" {
			// After a restart no hotel holds the build until something asks
			// for it; a client that only retries the create would wait forever.
			b.ensureBuilds(img, g)
			compatErr(w, 409, "image_not_ready", "image "+id+" is not built yet; poll /v1/images/"+id, 5)
			return
		}
		native["image"] = ref
		res = map[string]any{"vcpu": img.CPU, "memory_gib": img.MemoryGiB, "disk_gib": img.DiskGiB}
	} else if ref, _ := req["image"].(string); ref != "" {
		native["image"] = ref
	} else if t, _ := req["template"].(string); t != "" {
		// Only the catalog templates map to the base image. An unknown name
		// is an error, never a silent base-image room.
		size, ok := compatTemplates[t]
		if !ok {
			compatErr(w, 404, "template_not_found", "no template "+t+"; see /v1/sandboxes/catalog", 0)
			return
		}
		native["image"] = "alpine:3.20"
		res = map[string]any{"vcpu": size[0], "memory_gib": size[1], "disk_gib": 10}
	} else {
		compatErr(w, 400, "invalid_source", "image_id is required", 0)
		return
	}
	if shape, ok := req["shape"].(map[string]any); ok { // the cloud API's size fields
		if v, ok := shape["vcpus"].(float64); ok && v > 0 {
			res["vcpu"] = int(v)
		}
		if v, ok := shape["memory_mib"].(float64); ok && v > 0 {
			res["memory_gib"] = int(math.Ceil(v / 1024))
		}
		if v, ok := shape["disk_gib"].(float64); ok && v > 0 {
			res["disk_gib"] = int(v)
		}
	}
	native["resources"] = res
	if env, ok := req["env"].(map[string]any); ok && len(env) > 0 {
		native["env"] = env // the hotel checks the names; the room needs them to run the task
	}
	net, nerr := compatNetwork(req["network"], req["network_allow"])
	if nerr != nil {
		compatErr(w, 400, nerr.code, nerr.msg, 0)
		return
	}
	native["network"] = net
	ttl := 3600
	if v, ok := req["lifetime_seconds"].(float64); ok && v > 0 {
		ttl = int(v)
	}
	if ttl > 48*3600 {
		ttl = 48 * 3600
	}
	native["ttl_seconds"] = ttl
	// Hotel choice: the guest's hotel set and sealed default apply; "sealed"
	// true or false in the request chooses explicitly.
	sealed, sealedField := req["sealed"].(bool)
	if sealedField {
		if sealed {
			pl.match = map[string]string{"sealed": "true"}
		} else {
			pl.exclude = map[string]string{"sealed": "true"}
		}
	}
	b.scope(g, &pl, false, sealedField)
	if len(pl.images) > 0 && !b.anyHotel(pl) {
		// Built, but not on a hotel this create may use (for example only on
		// an unsealed hotel for a sealed create). Build it there and say so.
		if img := b.compatImageByID(req["image_id"]); img != nil {
			b.ensureBuilds(img, g)
		}
		compatErr(w, 409, "image_not_ready", "the image is not built yet on a hotel this create may use (sealed hotels unless the create says \"sealed\": false); the broker is building it there, retry", 10)
		return
	}
	if e, retry := b.admit(g, 1); e != nil {
		compatErr(w, e.status, e.code, e.msg, retry)
		return
	}
	out := b.createMany(r.Context(), g, native, 1, time.Now(), pl)[0]
	if out.status != 202 {
		code, msg := "create_failed", "the hotel refused the room"
		if e, ok := out.doc["error"].(map[string]string); ok {
			code, msg = e["code"], e["message"]
		} else if len(out.body) > 0 {
			var d map[string]any
			if json.Unmarshal(reEnvelope(out.status, out.header, out.body), &d) == nil {
				if dd, ok := d["detail"].(map[string]any); ok {
					code, _ = dd["error"].(string)
					msg, _ = dd["message"].(string)
				}
			}
		}
		ra, _ := strconv.Atoi(out.header.Get("Retry-After"))
		compatErr(w, out.status, code, msg, ra)
		return
	}
	bid, _ := out.doc["id"].(string)
	b.mu.Lock()
	rm := b.byBID(bid)
	u := ""
	if rm != nil {
		u = rm.uuid
	}
	b.mu.Unlock()
	writeJSON(w, 201, compatView(out.doc, u))
}

// compatNetwork turns the client network fields into the hotel network
// object. The client sends a mode name ("internet", "deny_all", "allowlist",
// or the old "none") with the list in network_allow, or the hotel object
// {"mode", "allow"} itself. "deny_all" and "none" become the hotel mode
// deny_all: the room keeps a network interface, so its policy can switch
// later. The hotel checks every entry.
func compatNetwork(mode, allow any) (map[string]any, *apiErr) {
	if obj, ok := mode.(map[string]any); ok {
		mode, allow = obj["mode"], obj["allow"]
	}
	list := []any{}
	switch a := allow.(type) {
	case nil:
	case []any:
		list = a
	default:
		return nil, &apiErr{400, "invalid_network_allowlist", "network_allow must be a list of strings"}
	}
	switch mode {
	case nil, "", "internet", "public":
		return map[string]any{"mode": "internet", "allow": []any{}}, nil
	case "deny_all", "none":
		return map[string]any{"mode": "deny_all", "allow": []any{}}, nil
	case "allowlist":
		if len(list) == 0 {
			return nil, &apiErr{400, "invalid_network_allowlist", "allowlist mode needs at least one network_allow entry"}
		}
		return map[string]any{"mode": "allowlist", "allow": list}, nil
	}
	return nil, &apiErr{400, "invalid_network_mode", fmt.Sprintf("network must be internet, deny_all or allowlist, not %v", mode)}
}

// compatSetNetwork switches a room's policy live: PUT /v1/sandboxes/{uuid}/network.
func (b *broker) compatSetNetwork(w http.ResponseWriter, r *http.Request, rm *room, id string) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req map[string]any
	if json.Unmarshal(raw, &req) != nil {
		compatErr(w, 400, "invalid_json", "request body is not JSON", 0)
		return
	}
	allow := req["allow"]
	if allow == nil {
		allow = req["network_allow"]
	}
	// A live change must name its mode. compatNetwork defaults a missing
	// mode to internet, which is right for a create but would turn a
	// malformed change into full internet access.
	if m, _ := req["mode"].(string); m == "" {
		compatErr(w, 400, "invalid_network_mode", "network change needs a mode: internet, deny_all or allowlist", 0)
		return
	}
	net, nerr := compatNetwork(req["mode"], allow)
	if nerr != nil {
		compatErr(w, 400, nerr.code, nerr.msg, 0)
		return
	}
	body, _ := json.Marshal(net)
	status, hdr, out, err := rm.h.do(r.Context(), "PUT", "/v1/sandboxes/"+url.PathEscape(rm.hid)+"/network", nil, body, 2*time.Minute)
	if err != nil {
		compatErr(w, 502, "hotel_unreachable", "the hotel did not answer", 5)
		return
	}
	copyRoomHeaders(w.Header(), hdr)
	var doc map[string]any
	if status != 200 || json.Unmarshal(out, &doc) != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(reEnvelope(status, hdr, out))
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "network": doc["network"]})
}

// compatView turns a hotel sandbox document into the client view.
func compatView(doc map[string]any, u string) map[string]any {
	v := map[string]any{}
	for k, x := range doc {
		v[k] = x
	}
	v["id"] = u
	v["hardware"] = "standard"
	if _, ok := v["state"]; !ok {
		v["state"] = "running"
	}
	if ttl, ok := doc["ttl_seconds"]; ok {
		v["lifetime_seconds"] = ttl
	}
	return v
}

func (b *broker) compatList(w http.ResponseWriter, r *http.Request, g *guestState) {
	c := &capture{hdr: http.Header{}, status: 200}
	q := r.URL.Query()
	q.Del("limit")
	q.Del("offset")
	r2 := r.Clone(r.Context())
	r2.URL.RawQuery = q.Encode()
	b.handleList(c, r2, g)
	var doc struct {
		Sandboxes []map[string]any `json:"sandboxes"`
	}
	_ = json.Unmarshal(c.buf.Bytes(), &doc)
	out := []any{}
	b.mu.Lock()
	for _, s := range doc.Sandboxes {
		bid, _ := s["id"].(string)
		if rm := b.byBID(bid); rm != nil {
			out = append(out, compatView(s, rm.uuid))
		}
	}
	b.mu.Unlock()
	writeJSON(w, 200, map[string]any{"sandboxes": out, "count": len(out)})
}

func (b *broker) compatQuota(w http.ResponseWriter, r *http.Request, g *guestState) {
	c := &capture{hdr: http.Header{}, status: 200}
	b.handleQuota(c, r, g)
	var doc map[string]any
	_ = json.Unmarshal(c.buf.Bytes(), &doc)
	free := b.freeRoomsFor(g)
	doc["admission_open"] = free > 0
	doc["available"] = map[string]any{"rooms": free}
	writeJSON(w, 200, doc)
}

func (b *broker) compatRoom(w http.ResponseWriter, r *http.Request, g *guestState, rest string) {
	id, tail, _ := strings.Cut(rest, "/")
	rm := b.roomByUUID(g, id)
	if rm == nil {
		b.compat.mu.Lock()
		t, dead := b.compat.tombs[id]
		b.compat.mu.Unlock()
		if dead && r.Method == "GET" && tail == "" {
			writeJSON(w, 200, map[string]any{"id": id, "state": "deleted", "cleanup_state": b.cleanupState(r.Context(), t.bid)})
			return
		}
		if dead && r.Method == "DELETE" && tail == "" {
			writeJSON(w, 200, map[string]any{"id": id, "state": "deleted", "cleanup_state": b.cleanupState(r.Context(), t.bid)})
			return
		}
		compatErr(w, 404, "sandbox_not_found", "no sandbox "+id, 0)
		return
	}
	bid := rm.id
	switch {
	case tail == "" && r.Method == "GET":
		status, _, out, err := rm.h.do(r.Context(), "GET", "/v1/sandboxes/"+url.PathEscape(rm.hid), nil, nil, 30*time.Second)
		if err != nil {
			compatErr(w, 502, "hotel_unreachable", "the hotel did not answer", 5)
			return
		}
		if status == 404 {
			writeJSON(w, 200, map[string]any{"id": id, "state": "deleted", "cleanup_state": "confirmed"})
			return
		}
		var doc map[string]any
		if status != 200 || json.Unmarshal(out, &doc) != nil {
			w.WriteHeader(status)
			_, _ = w.Write(reEnvelope(status, http.Header{}, out))
			return
		}
		writeJSON(w, 200, compatView(doc, id))
	case tail == "" && r.Method == "DELETE":
		c := &capture{hdr: http.Header{}, status: 200}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/v1/sandboxes/" + bid
		b.handleRoom(c, r2, g, bid)
		if c.status != 204 && c.status != 404 {
			b.flushCompat(w, c, rm)
			return
		}
		b.compat.mu.Lock()
		b.compat.tombs[id] = compatTomb{bid: bid, at: time.Now()}
		for eid, ex := range b.compat.execs { // results of a deleted room have no reader
			if ex.room == id {
				delete(b.compat.execs, eid)
			}
		}
		b.compat.mu.Unlock()
		b.markDirty()
		writeJSON(w, 200, map[string]any{"id": id, "state": "deleted", "cleanup_state": b.cleanupState(r.Context(), bid)})
	case tail == "exec" && r.Method == "POST":
		b.compatIdem(w, r, g, func(w http.ResponseWriter, raw []byte) {
			body, timeout, err := compatExecBody(raw, b.maxExec())
			if err != nil {
				compatErr(w, 400, "invalid_exec", err.Error(), 0)
				return
			}
			status, doc, herr := b.hotelExec(r.Context(), rm, body, timeout)
			if herr != nil {
				compatErr(w, 502, "hotel_unreachable", "the hotel did not answer", 5)
				return
			}
			if status != 200 {
				out, _ := json.Marshal(doc)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write(reEnvelope(status, http.Header{}, out))
				return
			}
			doc["state"] = "exited"
			if t, _ := doc["timed_out"].(bool); t {
				doc["state"] = "timed_out"
			}
			writeJSON(w, 200, doc)
		})
	case tail == "network" && (r.Method == "PUT" || r.Method == "POST" || r.Method == "PATCH"):
		b.compatSetNetwork(w, r, rm, id)
	case tail == "execs" && r.Method == "POST":
		b.compatIdem(w, r, g, func(w http.ResponseWriter, raw []byte) { b.compatExecStart(w, rm, id, raw) })
	case strings.HasPrefix(tail, "execs/"):
		b.compatExecPoll(w, r, id, strings.TrimPrefix(tail, "execs/"))
	case tail == "files" && r.Method == "PUT":
		b.compatPutFile(w, r, rm)
	case tail == "files" && r.Method == "GET":
		b.compatGetFile(w, r, rm)
	case tail == "tar" && r.Method == "PUT":
		b.compatPutTar(w, r, rm)
	case tail == "tar" && r.Method == "GET":
		b.compatGetTar(w, r, rm)
	case tail == "stat" && r.Method == "GET":
		b.compatStat(w, r, rm)
	case tail == "lifetime" && (r.Method == "POST" || r.Method == "PATCH"):
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		ttl := 3600.0
		if v, ok := req["extend_by_seconds"].(float64); ok && v > 0 {
			// Relative: the hotel's heartbeat takes an absolute TTL, so add
			// to what the room has left (sending v alone shortened rooms).
			left := b.roomSecondsLeft(r.Context(), rm)
			if left < 0 {
				compatErr(w, 502, "hotel_unreachable", "the hotel did not say when the room ends", 5)
				return
			}
			ttl = left + v
		} else if v, ok := req["lifetime_seconds"].(float64); ok && v > 0 {
			ttl = v // absolute from now, the cloud API's field
		} else if v, ok := req["ttl_seconds"].(float64); ok && v > 0 {
			ttl = v
		}
		if ttl > 48*3600 {
			ttl = 48 * 3600
		}
		hb, _ := json.Marshal(map[string]any{"ttl_seconds": int(ttl)})
		status, hdr, out, err := rm.h.do(r.Context(), "POST", "/v1/sandboxes/"+url.PathEscape(rm.hid)+"/heartbeat", nil, hb, 30*time.Second)
		if err != nil {
			compatErr(w, 502, "hotel_unreachable", "the hotel did not answer", 5)
			return
		}
		b.writeHotelCompat(w, status, hdr, out, rm, id)
	default:
		// Everything else passes through to the hotel (processes, heartbeat, wait, ...).
		c := &capture{hdr: http.Header{}, status: 200}
		r2 := r.Clone(r.Context())
		suffix := ""
		if tail != "" {
			suffix = "/" + tail
		}
		r2.URL.Path = "/v1/sandboxes/" + bid + suffix
		b.handleRoom(c, r2, g, bid+suffix)
		b.flushCompat(w, c, rm)
	}
}

func (b *broker) cleanupState(ctx context.Context, bid string) string {
	hotelID, hid, _ := strings.Cut(bid, ".")
	h := b.hotelByID(hotelID)
	if h == nil {
		return "confirmed"
	}
	status, _, _, err := h.do(ctx, "GET", "/v1/sandboxes/"+url.PathEscape(hid), nil, nil, 15*time.Second)
	if err == nil && status == 404 {
		return "confirmed"
	}
	return "pending"
}

func (b *broker) writeHotelCompat(w http.ResponseWriter, status int, hdr http.Header, out []byte, rm *room, u string) {
	if status >= 400 {
		out = reEnvelope(status, hdr, out)
	} else {
		out = bytes.ReplaceAll(out, []byte(`"`+rm.hid+`"`), []byte(`"`+u+`"`))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

func (b *broker) flushCompat(w http.ResponseWriter, c *capture, rm *room) {
	out := c.buf.Bytes()
	for k, v := range c.hdr {
		w.Header()[k] = v
	}
	if c.status >= 400 {
		out = reEnvelope(c.status, c.hdr, out)
		w.Header().Del("Content-Length")
	} else if rm != nil && strings.HasPrefix(c.hdr.Get("Content-Type"), "application/json") {
		out = bytes.ReplaceAll(out, []byte(`"`+rm.id+`"`), []byte(`"`+rm.uuid+`"`))
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(c.status)
	_, _ = w.Write(out)
}

// compatExecBody translates a client exec body to a hotel exec body.
func compatExecBody(raw []byte, maxExec int) (map[string]any, int, error) {
	var req map[string]any
	if json.Unmarshal(raw, &req) != nil {
		return nil, 0, fmt.Errorf("request body is not JSON")
	}
	cmd := req["command"]
	if cmd == nil {
		cmd = req["cmd"]
	}
	if cmd == nil {
		return nil, 0, fmt.Errorf("cmd is required")
	}
	list, ok := cmd.([]any)
	if !ok || len(list) == 0 {
		return nil, 0, fmt.Errorf("cmd must be a non-empty list of strings")
	}
	argv := make([]string, 0, len(list))
	for _, x := range list {
		s, ok := x.(string)
		if !ok || s == "" {
			return nil, 0, fmt.Errorf("cmd must be a non-empty list of strings")
		}
		argv = append(argv, s)
	}
	body := map[string]any{"cmd": argv}
	for _, k := range []string{"cwd", "env", "user", "stdin"} {
		if v, ok := req[k]; ok && v != nil {
			body[k] = v
		}
	}
	timeout := maxExec
	if v, ok := req["timeout_seconds"].(float64); ok && v > 0 {
		timeout = int(v)
	}
	return body, timeout, nil
}

func (b *broker) compatExecStart(w http.ResponseWriter, rm *room, roomUUID string, raw []byte) {
	body, timeout, err := compatExecBody(raw, b.maxExec())
	if err != nil {
		compatErr(w, 400, "invalid_exec", err.Error(), 0)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	ex := &compatExec{ID: newUUID(), room: roomUUID, done: make(chan struct{}), cancel: cancel, state: "running"}
	b.compat.mu.Lock()
	b.compat.execs[ex.ID] = ex
	b.compat.mu.Unlock()
	go func() {
		defer close(ex.done)
		status, doc, herr := b.hotelExec(ctx, rm, body, timeout)
		b.compat.mu.Lock()
		defer b.compat.mu.Unlock()
		ex.doneAt = time.Now()
		switch {
		case ex.state == "killed":
		case herr != nil:
			ex.state, ex.result = "lost", map[string]any{"message": "the hotel did not answer"}
		case status != 200:
			ex.state, ex.result = "lost", map[string]any{"message": fmt.Sprintf("hotel answered %d", status)}
		default:
			ex.state, ex.result = "exited", doc
			if t, _ := doc["timed_out"].(bool); t {
				ex.state = "timed_out"
			}
		}
	}()
	writeJSON(w, 202, map[string]any{"exec_id": ex.ID, "state": "running"})
}

func (b *broker) compatExecPoll(w http.ResponseWriter, r *http.Request, roomUUID, execID string) {
	b.compat.mu.Lock()
	ex := b.compat.execs[execID]
	b.compat.mu.Unlock()
	if ex == nil || ex.room != roomUUID {
		compatErr(w, 404, "exec_not_found", "no command "+execID, 0)
		return
	}
	if r.Method == "DELETE" {
		b.compat.mu.Lock()
		if ex.state == "running" {
			ex.state = "killed"
			ex.result = map[string]any{"message": "stopped on request; the command may run on inside the room until its timeout"}
		}
		b.compat.mu.Unlock()
		ex.cancel()
	} else if wait, _ := strconv.Atoi(r.URL.Query().Get("wait")); wait > 0 {
		if wait > 25 {
			wait = 25
		}
		select {
		case <-ex.done:
		case <-time.After(time.Duration(wait) * time.Second):
		case <-r.Context().Done():
		}
	}
	b.compat.mu.Lock()
	out := map[string]any{"exec_id": ex.ID, "state": ex.state}
	for k, v := range ex.result {
		out[k] = v
	}
	b.compat.mu.Unlock()
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- files through exec

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }

func (b *broker) runScript(ctx context.Context, rm *room, script string, stdin string, timeout int) (map[string]any, error) {
	body := map[string]any{"cmd": []string{"sh", "-c", script}, "user": "root"}
	if stdin != "" {
		body["stdin"] = stdin
	}
	status, doc, err := b.hotelExec(ctx, rm, body, timeout)
	if err != nil {
		// A transport error names the hotel's private API URL; guests see the hotel id only.
		return nil, fmt.Errorf("hotel %s did not answer", rm.h.cfg.ID)
	}
	if status != 200 {
		return nil, fmt.Errorf("hotel answered %d", status)
	}
	return doc, nil
}

func exitCode(doc map[string]any) int {
	if v, ok := doc["exit_code"].(float64); ok {
		return int(v)
	}
	return -1
}

func (b *broker) compatPutFile(w http.ResponseWriter, r *http.Request, rm *room) {
	p := r.URL.Query().Get("path")
	if !strings.HasPrefix(p, "/") {
		compatErr(w, 400, "invalid_path", "path must be absolute", 0)
		return
	}
	data, _ := io.ReadAll(io.LimitReader(r.Body, fileMaxBytes+1))
	if len(data) > fileMaxBytes {
		compatErr(w, 413, "file_too_large", "file is larger than the broker limit", 0)
		return
	}
	mode := ""
	if m := r.URL.Query().Get("mode"); m != "" {
		if n, err := strconv.Atoi(m); err == nil { // clients send the mode as a decimal integer
			mode = strconv.FormatInt(int64(n), 8)
		}
	}
	script := "set -e; mkdir -p " + shq(path.Dir(p)) + "; base64 -d > " + shq(p)
	if mode != "" {
		script += "; chmod " + mode + " " + shq(p)
	}
	doc, err := b.runScript(r.Context(), rm, script, base64.StdEncoding.EncodeToString(data), 900)
	if err != nil || exitCode(doc) != 0 {
		compatErr(w, 500, "file_write_failed", fmt.Sprint(err, doc["stderr"]), 0)
		return
	}
	writeJSON(w, 200, map[string]any{"path": p, "written": len(data)})
}

func (b *broker) compatGetFile(w http.ResponseWriter, r *http.Request, rm *room) {
	p := r.URL.Query().Get("path")
	doc, err := b.runScript(r.Context(), rm, "test -f "+shq(p)+" || exit 44; base64 "+shq(p), "", 900)
	if err != nil {
		compatErr(w, 502, "hotel_unreachable", err.Error(), 5)
		return
	}
	if exitCode(doc) == 44 {
		compatErr(w, 404, "file_not_found", "no file "+p, 0)
		return
	}
	if exitCode(doc) != 0 {
		compatErr(w, 500, "file_read_failed", fmt.Sprint(doc["stderr"]), 0)
		return
	}
	s, _ := doc["stdout"].(string)
	data, derr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if derr != nil || doc["truncated"] == true {
		compatErr(w, 413, "file_too_large", "file is larger than the exec output limit", 0)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func (b *broker) compatPutTar(w http.ResponseWriter, r *http.Request, rm *room) {
	p := r.URL.Query().Get("path")
	if !strings.HasPrefix(p, "/") || p == "/" {
		compatErr(w, 400, "invalid_path", "path must be absolute and not /", 0)
		return
	}
	data, _ := io.ReadAll(io.LimitReader(r.Body, fileMaxBytes+1))
	if len(data) > fileMaxBytes {
		compatErr(w, 413, "file_too_large", "archive is larger than the broker limit", 0)
		return
	}
	flag := "-xf"
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		flag = "-xzf"
	}
	script := "set -e; mkdir -p " + shq(p) + "; base64 -d | tar --no-same-owner " + flag + " - -C " + shq(p)
	doc, err := b.runScript(r.Context(), rm, script, base64.StdEncoding.EncodeToString(data), 900)
	if err != nil || exitCode(doc) != 0 {
		compatErr(w, 500, "tar_extract_failed", fmt.Sprint(err, doc["stderr"]), 0)
		return
	}
	writeJSON(w, 200, map[string]any{"path": p, "written": len(data)})
}

func (b *broker) compatGetTar(w http.ResponseWriter, r *http.Request, rm *room) {
	p := r.URL.Query().Get("path")
	ex := ""
	for _, e := range r.URL.Query()["exclude"] {
		ex += " --exclude=" + shq(e)
	}
	doc, err := b.runScript(r.Context(), rm, "test -d "+shq(p)+" || exit 44; tar -czf -"+ex+" -C "+shq(p)+" . | base64", "", 900)
	if err != nil {
		compatErr(w, 502, "hotel_unreachable", err.Error(), 5)
		return
	}
	if exitCode(doc) == 44 {
		compatErr(w, 404, "path_not_found", "no directory "+p, 0)
		return
	}
	s, _ := doc["stdout"].(string)
	data, derr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if doc["truncated"] == true {
		compatErr(w, 413, "file_too_large", "the archive is larger than the exec output limit; fetch the files one by one", 0)
		return
	}
	if exitCode(doc) != 0 || derr != nil {
		msg := strings.TrimSpace(fmt.Sprint(doc["stderr"]))
		if msg == "" || msg == "<nil>" {
			msg = "tar failed inside the room"
		}
		compatErr(w, 500, "tar_failed", msg, 0)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func (b *broker) compatStat(w http.ResponseWriter, r *http.Request, rm *room) {
	p := r.URL.Query().Get("path")
	doc, err := b.runScript(r.Context(), rm, "if [ -d "+shq(p)+" ]; then echo dir; elif [ -f "+shq(p)+" ]; then echo file; elif [ -e "+shq(p)+" ]; then echo other; else exit 44; fi", "", 30)
	if err != nil {
		compatErr(w, 502, "hotel_unreachable", err.Error(), 5)
		return
	}
	if exitCode(doc) == 44 {
		compatErr(w, 404, "path_not_found", "no path "+p, 0)
		return
	}
	kind := strings.TrimSpace(fmt.Sprint(doc["stdout"]))
	writeJSON(w, 200, map[string]any{"path": p, "exists": true, "is_dir": kind == "dir", "is_file": kind == "file"})
}

// roomSecondsLeft asks the hotel when the room ends. -1 when it cannot say.
func (b *broker) roomSecondsLeft(ctx context.Context, rm *room) float64 {
	status, _, out, err := rm.h.do(ctx, "GET", "/v1/sandboxes/"+url.PathEscape(rm.hid), nil, nil, 10*time.Second)
	if err != nil || status != 200 {
		return -1
	}
	var doc struct {
		ExpiresAt string `json:"expires_at"`
	}
	if json.Unmarshal(out, &doc) != nil || doc.ExpiresAt == "" {
		return -1
	}
	t, err := time.Parse(time.RFC3339Nano, doc.ExpiresAt)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, doc.ExpiresAt); err != nil {
			return -1
		}
	}
	left := time.Until(t).Seconds()
	if left < 0 {
		left = 0
	}
	return left
}

// freeRoomsFor counts free slots on the hotels the guest may use. Counting
// the whole chain told a guest whose only hotel is full that rooms are free.
func (b *broker) freeRoomsFor(g *guestState) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	free := 0
	for _, h := range b.hotelList() {
		if !h.ok || !g.limits.allows(h.cfg.ID) {
			continue
		}
		if f := h.slots - h.used(); f > 0 {
			free += f
		}
	}
	return free
}
