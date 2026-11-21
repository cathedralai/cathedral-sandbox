// Thin broker ("central booking") in front of room hosts ("hotels").
//
// It does four things and nothing more:
//   - Scatter: a create goes to one hotel, picked at random with weight = free rooms.
//     Each hotel has a bounded number of creates in flight.
//   - Gather: list, quota and usage ask every hotel in parallel and merge.
//   - Route: a room id is "<hotel>.<hotel room id>"; calls on a room go to its hotel.
//   - Show: /<guest>/live is a live view of the hotels and the guest's rooms.
//
// Hotel addresses, hotel keys, guest keys and view tokens come from a private
// config file. Guest keys and view tokens are stored as SHA-256 hashes only.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed live.html
var liveHTML []byte

type hotelConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Threads     int    `json:"threads"`
	RAMGiB      int    `json:"ram_gib"`
	API         string `json:"api"`    // base URL of the hotel /v1 API (private path)
	Health      string `json:"health"` // base URL of the hotel /room/health endpoint
	KeyFile     string `json:"key_file"`
	Concurrency int    `json:"concurrency"` // creates in flight at this hotel
	Drain       bool   `json:"drain"`       // true: no new rooms here; existing rooms keep working
	// DataConns: data connections to the hotel (room calls; each exec holds
	// one for its run). 0: concurrency + 64. DataConnWaitSeconds: how long a
	// call waits for a free one before 503 sold_out; 0: 10 s, -1: until the
	// call's own deadline (hotelconns.go, AB#819).
	DataConns           int `json:"data_conns,omitempty"`
	DataConnWaitSeconds int `json:"data_conn_wait_seconds,omitempty"`
	// Labels describe the hotel, for example {"sealed": "true"}. A guest can
	// ask for rooms only on hotels with (or without) some labels.
	Labels   map[string]string `json:"labels"`
	Sealed   bool              `json:"sealed"`    // true: a sealed hotel (SEV-SNP guest); only creates with "sealed": true go here
	MaxSlots int               `json:"max_slots"` // > 0: cap on the slots the hotel reports, set at the broker (no hotel restart)
	// ReservedFor: a guest id. Only that guest may use the hotel; every other
	// guest treats it as denied (capacity.go). Empty: a pool hotel.
	ReservedFor string `json:"reserved_for,omitempty"`
	// LentFrom: the guest a reserved hotel was lent from (lend.go). The hotel
	// is in the pool, and that guest's rooms never go there until reclaim.
	// LentReportID: the SEV-SNP REPORT_ID of the launch at lend time; reclaim
	// needs a different one (a new launch). Set by PATCH {"lend": true}.
	LentFrom     string `json:"lent_from,omitempty"`
	LentReportID string `json:"lent_report_id,omitempty"`
	// MinerHotkey: the SS58 hotkey of the SN94 miner that runs the hotel.
	// The hotel then carries the labels miner=true and miner_hotkey=<key>,
	// so a guest policy can deny miner hotels ({"label": {"miner": "true"}}).
	MinerHotkey string `json:"miner_hotkey,omitempty"`
	// RequireAttestation was the config file hotel's opt-in to the SEV-SNP
	// gate. Since AB#596 every sealed hotel is gated (admission.go), so it is
	// redundant; it still loads, needs "sealed": true, and logs once.
	RequireAttestation bool `json:"require_attestation,omitempty"`
	// SealedAdmission: absent or "gate" (default) gates a sealed hotel.
	// "off" skips the gate, for an operator hotel in the config file only:
	// the emergency ops escape. A miner hotel or a joined hotel with "off"
	// is refused (admission.go).
	SealedAdmission string `json:"sealed_admission,omitempty"`
	// TLSSPKISHA256 is derived from a miner hotel's verified SNP binding at
	// join and persisted for safe reconnect after a broker restart.
	TLSSPKISHA256 string `json:"tls_spki_sha256,omitempty"`
	// DrainNotice: the miner's signed planned-maintenance notice, set by
	// PATCH {"drain": true, "drain_notice": ...} (drain_notice.go).
	DrainNotice *drainNoticeRecord `json:"drain_notice,omitempty"`
	// GuestTLS (AB#378): a sealed hotel reached only over the TLS key its
	// guest made and named in its attested binding, with the hotel key
	// installed in the guest (hotel_key_source "install"), as a miner hotel
	// is. The broker verifies the key without sending the hotel key and pins
	// it (miner_tls.go syncGuestPin); a config file never names the pin.
	GuestTLS bool `json:"guest_tls,omitempty"`
	// HotelKeyInstallSigningKeyFile (AB#817): a "guest_tls" config hotel
	// whose guest takes its hotel key only by install (room-kit
	// SEALED_MINER=1). The file holds base64 of an Ed25519 seed (mode 600);
	// its public key must be in the guest's SEALED_HOTEL_KEY_INSTALL_SIGNERS.
	// The broker installs key_file's key after each new pin
	// (hotel_key_install.go), and admission waits for it.
	HotelKeyInstallSigningKeyFile string `json:"hotel_key_install_signing_key_file,omitempty"`
	// Commitment: the slots and daily hours a miner hotel declares at join
	// (commitment.go). Nil: none declared.
	Commitment *capacityCommitment `json:"commitment,omitempty"`
	// AlertChatID: the miner operator's Telegram chat for the first missed
	// heartbeat of this hotel (alerts.go). Empty: a log line only.
	AlertChatID string `json:"alert_chat_id,omitempty"`
	// DiskExtraGiB: the disk this hotel may give rooms above the base 10 GiB
	// each, summed over its rooms (disk.go, AB#831). Nil: no disk limit.
	// 0: rooms of 10 GiB or less only.
	DiskExtraGiB *int `json:"disk_extra_gib,omitempty"`
	// DiskAdmitUsedPct: admit by the scratch the hotel really uses, not by
	// the rooms' disk limits (disk.go, AB#831 50 GiB default). Set, the hotel
	// takes any room of any disk while its room_data_used_pct is under this
	// value and none at or above it; disk_extra_gib is not counted. Nil: the
	// disk_extra_gib rule above.
	DiskAdmitUsedPct *float64 `json:"disk_admit_used_pct,omitempty"`
	// MemFullPct: this hotel's memory limit for new rooms, in place of the
	// broker-wide mem_full_pct (placement.go memFull, AB#855). A sealed hotel
	// that holds many rooms needs a lower mark than a plain one. Nil: the
	// broker-wide value. 1 to 100. PATCH sets or clears it live.
	MemFullPct *float64 `json:"mem_full_pct,omitempty"`
}

type guestConfig struct {
	ID        string `json:"id"`
	KeySHA256 string `json:"key_sha256"` // empty: the guest has a view only
	// NextKeySHA256 is accepted alongside key_sha256 for the same guest while
	// a key rotates: the client moves to the new key, then the old hash is
	// removed. Rooms stay with the guest throughout, so nothing is cut off.
	NextKeySHA256   string `json:"next_key_sha256,omitempty"`
	ViewTokenSHA256 string `json:"view_token_sha256"` // token for /<id>/live
	Ops             bool   `json:"ops"`               // may run the probe and reset the broker counters
	// LiveShares lets this guest mint share links to its live view (AB#584).
	// Off unless set: with it off, /v1/live/shares answers 403 and no share
	// link or cookie opens the view.
	LiveShares  bool `json:"live_shares,omitempty"`
	guestLimits      // max_rooms, max_creates_per_minute, default_sealed, hotels (guests.go)
}

type config struct {
	Listen         string        `json:"listen"`
	StateDir       string        `json:"state_dir"` // optional: keeps probe results across restarts
	Hotels         []hotelConfig `json:"hotels"`
	Guests         []guestConfig `json:"guests"`
	InsecureCookie bool          `json:"insecure_cookie"` // true only for plain-HTTP local tests
	// MaxExecSeconds is the longest exec the broker accepts (default 14,400).
	// Keep it at or below the hotels' CATHEDRAL_SANDBOX_EXEC_TIMEOUT_MAX.
	MaxExecSeconds int `json:"max_exec_seconds"`
	// MaxQueueWaitSeconds: a create that waits longer than this for a create
	// slot at its hotel moves to another eligible hotel (default 10; -1: never).
	MaxQueueWaitSeconds float64 `json:"max_queue_wait_seconds"`
	// UncertainCreateHoldSeconds: how long a metered guest's create attempt
	// whose answer was lost, and whose reap found no room, still counts
	// against its cap (allowance.go). 0 or absent: the create timeout to a
	// hotel (hotelCreateTimeout, 720); less is refused.
	UncertainCreateHoldSeconds int `json:"uncertain_create_hold_seconds,omitempty"`
	// MemFullPct: a hotel whose host memory use is at or above this percent
	// takes no new rooms (default 90; -1: no memory limit). Slots come from an
	// install-time sizing with memory overcommit, so they cannot see rooms
	// that use their full memory limit.
	MemFullPct float64 `json:"mem_full_pct"`
	// PrewarmCatalog (default off): when a hotel comes up, pull the live
	// catalog images on it, and prefer hotels that hold a create's image.
	// The scratch disk of a sealed hotel is wiped every boot (AB#532).
	PrewarmCatalog bool `json:"prewarm_catalog"`
	// PrewarmCatalogHotels narrows prewarm_catalog to these hotel ids, for a
	// one-hotel canary. Empty: every hotel. Each id must be a hotel in hotels
	// (the config file), and the list needs prewarm_catalog on. Unlike
	// terminal_hotels, an id that is not known yet is refused: a typo would
	// leave the canary cold and its measurement would say nothing.
	PrewarmCatalogHotels []string `json:"prewarm_catalog_hotels,omitempty"`
	// PreferGuestWarm (default on): prefer a hotel where the create's guest
	// prefetched the create's image (POST /v1/images/prefetch or a compat
	// import) since the hotel last came up. false: guest prefetches pull
	// but never steer creates (AB#859).
	PreferGuestWarm *bool `json:"prefer_guest_warm,omitempty"`
	// OperatorKeySHA256 is the SHA-256 of the operator key. It allows hotel
	// join, change and leave at runtime (hotels.go). Empty: no operator routes.
	OperatorKeySHA256 string `json:"operator_key_sha256"`
	// MinerEnrollKeySHA256 permits only verified miner joins, miner reads,
	// drain=true, and empty miner leaves through the hotel admin routes.
	MinerEnrollKeySHA256 string `json:"miner_enroll_key_sha256,omitempty"`
	// OperatorReadKeySHA256 is the SHA-256 of a read-only operator key. It
	// allows only GET /v1/broker/capacity with the operator view (every
	// hotel). It cannot join, change or leave hotels or touch guests. The
	// admin fleet feed uses it, so a leaked feed key cannot change the fleet.
	OperatorReadKeySHA256 string `json:"operator_read_key_sha256,omitempty"`
	// MeterKeySHA256 is the SHA-256 of the meter key (AB#890, meter.go). It
	// allows only GET /v1/broker/guests/{id}/rooms and POST
	// /v1/broker/guests/{id}/freeze-all: an external meter reads one guest's
	// rooms and freezes them when that guest's account runs out. Empty: both
	// routes answer 404.
	MeterKeySHA256 string `json:"meter_key_sha256,omitempty"`
	// MinerHotkeyCaps is the operator-approved maximum number of joined hotels
	// per miner hotkey. Miner joins without an entry are refused.
	MinerHotkeyCaps map[string]int `json:"miner_hotkey_caps,omitempty"`
	// MinerMaxHotels is the operator-approved maximum across all miner hotkeys.
	// Zero refuses miner joins; pending and draining hotels count.
	MinerMaxHotels int `json:"miner_max_hotels,omitempty"`
	// MinerProbationSeconds: a joined miner hotel takes test traffic only
	// for this long (observed time) and graduates to the shared pool at
	// MinerProbationMinUptimePct verified uptime (probation.go). 0: off.
	MinerProbationSeconds      float64 `json:"miner_probation_seconds,omitempty"`
	MinerProbationMinUptimePct float64 `json:"miner_probation_min_uptime_pct,omitempty"`
	// Room caps on miner hotels (placement.go, AB#335). Both are off at 0.
	// MinerMaxRoomsPerHotkey caps the rooms of one miner hotkey across all
	// its hotels. MinerPoolShare (0 < x < 1) caps the rooms on miner hotels
	// in the shared sealed pool at that share of the pool when it is full.
	MinerMaxRoomsPerHotkey int     `json:"miner_max_rooms_per_hotkey,omitempty"`
	MinerPoolShare         float64 `json:"miner_pool_share,omitempty"`
	// MinerMinCommitment is the floor a miner join's commitment must meet
	// (commitment.go). Nil or zero: a commitment is optional.
	MinerMinCommitment *capacityCommitment `json:"miner_min_commitment,omitempty"`
	// Admission of sealed hotels (admission.go). The top-level
	// SealedAdmission loads only as absent or "on": the gate cannot be
	// turned off for every hotel or for joined hotels. The ops escape is
	// "sealed_admission": "off" on one operator hotel's entry.
	SealedAdmission    string   `json:"sealed_admission,omitempty"`
	SealedMeasurements []string `json:"sealed_measurements,omitempty"` // a gated hotel's measurement must be one of these; empty refuses every gated hotel
	SealedHostData     []string `json:"sealed_host_data,omitempty"`    // non-empty: its HOST_DATA must be one of these
	// An optional Genoa SNP firmware component floor. Zero leaves it unset
	// until patched hosts are available. It does not prove the OEM PI fix.
	MinGenoaSNPSPL     int     `json:"min_genoa_snp_spl,omitempty"`
	AttestTTLSeconds   float64 `json:"attest_ttl_seconds,omitempty"`   // a pass is good this long (default 600)
	AttestEverySeconds float64 `json:"attest_every_seconds,omitempty"` // check a passed hotel again this often (default 60)
	// RequireSealedGuestTLS (AB#378): every sealed hotel is reached only over
	// its attested guest TLS key. A sealed config hotel must set "guest_tls":
	// true, and a sealed join must pass the keyless HTTPS bootstrap. Off by
	// default until every sealed hotel runs a guest that installs its key.
	RequireSealedGuestTLS bool `json:"require_sealed_guest_tls,omitempty"`
	// AMDVerifier runs room-kit/verify_receipts.py on a sealed hotel's
	// attestation to check the AMD chain (amd_chain.go). Required for miner hotels.
	AMDVerifier *amdVerifierConfig `json:"amd_verifier,omitempty"`
	// EscapeNonceAllowPlaintext is a leftover key. Live configs still set
	// it to false. The loader accepts false and logs that it is ignored;
	// true is refused so a leftover "on" cannot start a broker. The nonce
	// is never sent in the clear.
	EscapeNonceAllowPlaintext *bool `json:"escape_nonce_allow_plaintext,omitempty"`
	// TerminalHotels names the operator hotels whose room kit runs a terminal
	// line through the runtime's exec, in the room (B154, hotel API b1739d0).
	// Room terminal routes reach only these hotels. Empty: no hotel. A miner
	// hotel never gets them, listed or not (terminalsRefused).
	TerminalHotels []string `json:"terminal_hotels,omitempty"`
	// ACMEDNS turns on the DNS-01 challenge service for Preview URL
	// certificates (acme_dns.go, AB#423). Absent: off.
	ACMEDNS *acmeDNSConfig `json:"acme_dns,omitempty"`
	// Alerts: where the missed heartbeat and customer drop alerts go
	// (alerts.go). Absent: log lines only.
	Alerts *alertsConfig `json:"alerts,omitempty"`
	// UsageMeterEverySeconds: a running room gets a usage reading this
	// often while hotel lists show it (usage_meter.go). 0: 60. The meter
	// needs state_dir; without one it is off.
	UsageMeterEverySeconds int `json:"usage_meter_every_seconds,omitempty"`
}

func (b *broker) maxExec() int {
	if b.cfg.MaxExecSeconds > 0 {
		return b.cfg.MaxExecSeconds
	}
	return defaultMaxExecSeconds
}

// Room states. One byte each, so the live view can send a grid as a string.
const (
	stFree     = '.'
	stCreating = 'c'
	stRunning  = 'r'
	stDeleting = 'd'
	stFailed   = 'f'
	stOther    = 'o' // a room of another guest (live view only)
)

const guestLabel = "broker_guest"

type room struct {
	id       string // broker id: <hotel>.<hotel room id>
	uuid     string // id shown to the Cathedral clients (compat.go)
	hid      string // hotel room id
	h        *hotel
	guest    string
	state    byte
	slot     int // index in the hotel grid, -1 if not drawn
	since    time.Time
	vanished time.Time
	diskGiB  int // resources.disk_gib; 0: unknown, the hotel default (disk.go)
	// deleteSent: the guest asked for the delete. A room marked deleting by
	// the sync loop alone may be listed again (a late list) and come back.
	deleteSent bool
	// End record inputs (ended.go, AB#864). born: when the broker first had
	// the room. reaped: a refused or cancelled create the guest never had.
	// labels, expiresAt, hotelDeath (a listed dead container's end_reason)
	// and hotelEnd (the hotel's "ended" entry) come from the hotel list;
	// hotelRestarted: the room went with a hotel API restart.
	born           time.Time
	reaped         bool
	labels         map[string]string
	expiresRaw     string
	expiresAt      time.Time
	hotelDeath     string
	hotelEnd       string
	hotelRestarted bool
}

type latencies struct{ hotel, queue, overhead []float64 }

type hotel struct {
	cfg       hotelConfig
	key       string
	client    *http.Client
	ctl       *http.Client // sync loop and hotel documents
	tlsPinErr error        // non-nil: guest TLS calls must not send the hotel key
	// guestPin is the verified guest TLS SPKI (miner_tls.go); nil: none yet.
	// Read on every TLS handshake, so atomic.
	guestPin atomic.Pointer[[sha256.Size]byte]
	cfgMu    sync.RWMutex // guards cfg.Labels, cfg.Drain, cfg.DrainNotice, cfg.ReservedFor, cfg.LentFrom and cfg.LentReportID, which PATCH changes while creates read them
	sem      chan struct{}
	conns    *connGate // data connection slots (hotelconns.go)

	// Guarded by broker.mu.
	slots        int
	grid         []*room
	rooms        map[string]*room // by hotel room id
	queued       int
	creating     int
	diskPending  int // extra disk GiB of the creates in queued and creating (disk.go)
	backoffUntil time.Time
	ok           bool            // health answered within okWindow, or room calls did (see syncHotel)
	warm         map[string]bool // catalog images pulled since the hotel last came up (prewarm.go)
	warmGen      int             // bumped when the hotel goes down, so a stale prewarm marks nothing
	prewarmFull  map[string]bool // catalog images whose pull was skipped for a full scratch, logged once (prewarm.go)
	healthLate   bool            // ok only because room calls answer; health is late
	lastOK       time.Time       // last good /room/health answer
	downSince    time.Time       // when ok last went false; zero while ok
	lastAnswer   atomic.Int64    // unix ns of the last room call the hotel answered (status < 500)
	healthMs     float64         // duration of the last /room/health call
	pinCheckedAt time.Time       // last keyless guest TLS check (syncGuestPin)
	pinErr       string          // why the last guest TLS check failed; "" after a pin
	pinChip      string          // CHIP_ID of the pinned guest TLS key's binding; a re-pin must match it
	keyInst      keyInstall      // hotel key install into the guest (hotel_key_install.go)
	// installer signs hotel key installs (hotel_key_install_signing_key_file);
	// nil: none. Set at config load only, never on a joined hotel.
	installer ed25519.PrivateKey
	// healthRuntime: the room runtime the hotel last reported in /room/health
	// ("runsc"...), or "" when it reported none. Atomic because isolationDoc
	// reads it with or without b.mu held.
	healthRuntime   atomic.Value // string
	kernelIsolation *bool        // kernel_isolation of the last good /room/health; nil when absent
	listOK          bool         // last room list answered
	apiStartedAt    string       // the hotel API's start time from its list (AB#864); "": not sent
	lastErr         string
	caps            map[string]any // capability probe results (probe.go)
	cpuPct          float64
	memPct          float64
	memGiB          float64
	roomDataPct     *float64 // live.room_data_used_pct of the last good health; nil: no reading (disk.go)
	load1           float64
	containers      int
	apiRunning      int
	apiDeleting     int
	removingDiskGiB int // usage.removing_disk_gib: disk of killed rooms not yet removed (AB#863, disk.go); 0 from an old hotel
	created         int
	failed          int
	rejected        int
	lat             latencies
	createEWMA      float64   // seconds, moving average of the hotel create call (placement.go)
	moved           int       // creates that left this hotel's queue for another hotel
	runtime         bool      // joined at runtime (hotels.go), not from the config file
	adm             admission // attestation gate of a joined sealed hotel (admission.go)
	prob            probation // miner probation (probation.go)
	probationOn     atomic.Bool
	delivery        delivery // delivered capacity against the commitment (commitment.go)
	// roomsUnchecked: loaded at start and no room list has answered since. A
	// reserved hotel takes no rooms until one has passed the fail-closed
	// check (lend.go). baselineTry: last REPORT_ID fetch for an unknown
	// lend baseline (lend.go).
	roomsUnchecked bool
	baselineTry    time.Time
	leaving        bool               // a leave passed its empty check; no new rooms (hotels.go)
	stop           context.CancelFunc // stops the sync loop when the hotel leaves
	syncDone       chan struct{}      // closed when the sync loop has returned: its last step is stored
	alerts         hotelAlerts        // missed heartbeat and drop alerts sent (alerts.go)
	// unreaped: create requests (by batch id) whose rooms on this hotel were
	// not confirmed removed after the hotel failed the create. The sync loop
	// keeps those rooms out of the guest's rooms and retries their removal
	// until a list shows none left (AB#338).
	unreaped map[string]*unreapedBatch
	// Guarded by broker.mu. guestWarm: per guest, the images that guest
	// prefetched here since the hotel last came up. guestWant: per guest,
	// the refs to pull again when the hotel comes back (prefetched without a
	// login, prewarm.go). AB#859.
	guestWarm map[string]map[string]bool
	guestWant map[string]map[string]time.Time
	// guestPinned: per guest, the refs this hotel pinned for it, so the replay
	// after a reboot pins them again (AB#860). Guarded by broker.mu.
	guestPinned map[string]map[string]bool
}

// unreapedBatch is one create request's leftover rooms on a hotel.
type unreapedBatch struct {
	guest string
	keep  map[string]bool // room ids the request did receive: never reaped
	busy  bool            // a removal pass is running
	// holdUntil: a metered guest's lost create whose reap found no room; the
	// record stays, unlisted, until then (allowance.go settleUncertain).
	holdUntil time.Time
}

type guestState struct {
	cfg      guestConfig
	created  int
	failed   int
	rejected int // 429 sent to the guest
	queued   int
	recent   []time.Time // create times in the last 60 s
	limits   guestLimits // from the config; an operator can change them at runtime (guests.go)
	pending  int         // rooms admitted and not yet placed or failed
	admits   []time.Time // admitted rooms in the last 60 s, for max_creates_per_minute
}

type broker struct {
	cfg              config
	terminalWSIdle   time.Duration // idle close of a terminal socket; 0: defaultTerminalWSIdle (terminal_ws.go)
	mu               sync.Mutex
	hset             atomic.Pointer[hotelSet] // hotels; replaced as a whole when one joins or leaves (hotels.go)
	hotelsMu         sync.Mutex               // serialises joins and leaves
	acmeDNS          acmeDNSState             // DNS-01 challenge records (acme_dns.go)
	hotelsMutationMu sync.Mutex               // keeps runtime mutations and their saves in order (hotels.json and hotel-lends.json)
	stateSaveMu      sync.Mutex               // one client-state save at a time, snapshot through rename (state.go)
	guests           map[string]*guestState
	allow            allowances                // metered guests (allowance.go)
	capsOnDisk       map[string]map[string]any // probe results read from state_dir at start
	probationFileMu  sync.Mutex                // serializes miner-probation.json writes (probation.go)
	probationSavedAt time.Time                 // guarded by mu
	lendsOnDisk      map[string]lendEntry      // lend state of hotels not in the config file now (lend.go); guarded by mu
	byKey            map[string]*guestState    // sha256(key) -> guest
	byUUID           map[string]*room
	compat           *compatState
	answers          *answerPool  // bytes of hotel exec answers being read on the compat routes (AB#752)
	nexec            *nativeExecs // background execs on the native route (nativeexec.go)
	prefetch         prefetchJobs
	started          time.Time
	alerts           *alerter // missed heartbeat and drop alerts (alerts.go)
	// requireAttestationNoted logs the require_attestation deprecation once
	// per broker, from the config file or a join (admission.go).
	requireAttestationNoted sync.Once

	// Durable client state (state.go).
	savedUUIDs map[string]string // broker room id -> client id, from the state file
	dirty      atomic.Bool

	// guestRooms is guest id -> hotel id -> hotel-local room id. It keeps
	// rooms after they leave the hotel list, so a guest can still read their
	// own receipts. Guarded by b.mu.
	guestRooms map[string]map[string]map[string]struct{}

	// tombs is guest id -> recent deletes by label, which also catch creates
	// in flight (inflight.go). Guarded by b.mu.
	tombs map[string][]tombstone

	// minerExits: miner hotels that went down holding customer rooms
	// (miner_exits.go). Guarded by b.mu.
	minerExits []*minerExit

	// ended is guest id -> end records of its rooms (ended.go); endSeq
	// numbers them in write order. Guarded by b.mu.
	ended  map[string]*guestEnded
	endSeq uint64

	// shares is sha256(share token) -> live view share link (live_share.go).
	// In memory only. Guarded by b.mu.
	shares map[string]*liveShare

	// usageMeter writes the usage readings of every room (usage_meter.go). nil:
	// no state_dir, metering is off.
	usageMeter *usageMeter
}

// A hotel counts as answering while its last good health answer is younger than okWindow.
const okWindow = 15 * time.Second

// byBID finds a room by its broker id. Caller holds b.mu.
func (b *broker) byBID(bid string) *room {
	hotelID, hid, _ := strings.Cut(bid, ".")
	if h := b.hotelByID(hotelID); h != nil {
		return h.rooms[hid]
	}
	return nil
}

// register gives a room its client UUID. Caller holds b.mu.
func (b *broker) register(rm *room) {
	if rm.uuid == "" {
		// After a restart, a room keeps the client id it had (state.go).
		if u := b.savedUUIDs[rm.id]; u != "" && b.byUUID[u] == nil {
			rm.uuid = u
			delete(b.savedUUIDs, rm.id)
		} else {
			rm.uuid = newUUID()
		}
	}
	b.byUUID[rm.uuid] = rm
	b.markDirty()
	if rm.h != nil {
		b.rememberGuestRoom(rm.guest, rm.h.cfg.ID, rm.hid)
	}
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func loadBroker(path string) (*broker, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c config
	// An unknown field is a typo, and a typo here fails open: "hotel" for
	// "hotels" gives a dedicated guest every hotel. Refuse the file.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := refusePlaintextEscapeNonce(c.EscapeNonceAllowPlaintext); err != nil {
		return nil, err
	}
	if c.MinGenoaSNPSPL < 0 || c.MinGenoaSNPSPL > 255 {
		return nil, errors.New("config: min_genoa_snp_spl must be an 8-bit SNP component value")
	}
	if c.MinerEnrollKeySHA256 != "" {
		hash, err := hex.DecodeString(c.MinerEnrollKeySHA256)
		if err != nil || len(hash) != sha256.Size {
			return nil, errors.New("config: miner_enroll_key_sha256 must be a SHA-256 hex digest")
		}
	}
	if c.MinerEnrollKeySHA256 != "" && strings.EqualFold(c.MinerEnrollKeySHA256, c.OperatorKeySHA256) {
		return nil, errors.New("config: miner enrollment key must differ from the operator key")
	}
	if c.OperatorReadKeySHA256 != "" {
		hash, err := hex.DecodeString(c.OperatorReadKeySHA256)
		if err != nil || len(hash) != sha256.Size {
			return nil, errors.New("config: operator_read_key_sha256 must be a SHA-256 hex digest")
		}
		if strings.EqualFold(c.OperatorReadKeySHA256, c.OperatorKeySHA256) || strings.EqualFold(c.OperatorReadKeySHA256, c.MinerEnrollKeySHA256) {
			return nil, errors.New("config: operator read key must differ from the operator key and the miner enrollment key")
		}
	}
	if c.MeterKeySHA256 != "" {
		hash, err := hex.DecodeString(c.MeterKeySHA256)
		if err != nil || len(hash) != sha256.Size {
			return nil, errors.New("config: meter_key_sha256 must be a SHA-256 hex digest")
		}
		if strings.EqualFold(c.MeterKeySHA256, c.OperatorKeySHA256) || strings.EqualFold(c.MeterKeySHA256, c.OperatorReadKeySHA256) || strings.EqualFold(c.MeterKeySHA256, c.MinerEnrollKeySHA256) {
			return nil, errors.New("config: meter key must differ from the operator key, the operator read key and the miner enrollment key")
		}
	}
	for hotkey, cap := range c.MinerHotkeyCaps {
		if !ss58RE.MatchString(hotkey) || cap < 1 {
			return nil, fmt.Errorf("config: miner_hotkey_caps requires an SS58 hotkey and a positive machine cap")
		}
	}
	if c.MinerMaxHotels < 0 {
		return nil, errors.New("config: miner_max_hotels must be positive when miner hotels are allowed")
	}
	if err := validateProbationConfig(c); err != nil {
		return nil, err
	}
	if c.MinerMaxRoomsPerHotkey < 0 {
		return nil, errors.New("config: miner_max_rooms_per_hotkey must be 0 (no cap) or more")
	}
	if c.MinerPoolShare != 0 && !(c.MinerPoolShare > 0 && c.MinerPoolShare < 1) {
		return nil, errors.New("config: miner_pool_share must be 0 (no cap) or between 0 and 1, exclusive")
	}
	if err := validateMinCommitment(c.MinerMinCommitment); err != nil {
		return nil, err
	}
	for _, id := range c.TerminalHotels {
		if id == "" || strings.Contains(id, ".") {
			return nil, fmt.Errorf("config: terminal_hotels entry %q must be a hotel id (non-empty, no dot)", id)
		}
	}
	switch c.SealedAdmission {
	case "", "on":
	case sealedAdmissionOff:
		return nil, errors.New(`config: top-level "sealed_admission": "off" is refused (AB#596): joined and miner hotels are always gated; to skip the gate for one operator hotel, set "sealed_admission": "off" on its entry in hotels`)
	default:
		return nil, fmt.Errorf(`config: sealed_admission %q: the top-level value can only be "on" (or absent)`, c.SealedAdmission)
	}
	alerts, err := newAlerter(c.Alerts)
	if err != nil {
		return nil, err
	}
	b := &broker{cfg: c, alerts: alerts, guests: map[string]*guestState{}, byKey: map[string]*guestState{}, byUUID: map[string]*room{}, compat: newCompat(), answers: newAnswerPool(), nexec: newNativeExecs(), shares: map[string]*liveShare{}, started: time.Now()}
	var optedIn []string // require_attestation hotels, for one deprecation line
	for _, hc := range c.Hotels {
		if err := validateSealedAdmission(hc); err != nil {
			return nil, err
		}
		if c.MinGenoaSNPSPL > 0 && hc.Sealed && hc.SealedAdmission == sealedAdmissionOff {
			return nil, fmt.Errorf("config: hotel %q: sealed_admission off bypasses min_genoa_snp_spl", hc.ID)
		}
		if hc.MinerHotkey != "" {
			return nil, fmt.Errorf("config: miner hotel %q must join with attested guest TLS", hc.ID)
		}
		if hc.Commitment != nil {
			return nil, fmt.Errorf("config: hotel %q: only a miner hotel declares a commitment, and miner hotels join at runtime", hc.ID)
		}
		if hc.RequireAttestation && !hc.Sealed {
			return nil, fmt.Errorf("config: hotel %q: require_attestation needs \"sealed\": true", hc.ID)
		}
		if err := validateGuestTLS(hc, c.RequireSealedGuestTLS); err != nil {
			return nil, err
		}
		if hc.RequireAttestation {
			optedIn = append(optedIn, hc.ID)
		}
		if hc.SealedAdmission == sealedAdmissionOff {
			log.Printf("config: hotel %s: sealed_admission off: the SEV-SNP admission gate is OFF for this hotel (ops escape, AB#596)", hc.ID)
		}
		if strings.Contains(hc.ID, ".") || hc.ID == "" {
			return nil, fmt.Errorf("hotel id %q: must be non-empty and have no dot", hc.ID)
		}
		if !validAlertChat(hc.AlertChatID) {
			return nil, fmt.Errorf("config: hotel %q: alert_chat_id must be a Telegram chat id (digits) or @channel", hc.ID)
		}
		if err := checkDataConnConfig(hc); err != nil {
			return nil, fmt.Errorf("config: hotel %q: %w", hc.ID, err)
		}
		if err := checkDiskConfig(hc); err != nil {
			return nil, fmt.Errorf("config: hotel %q: %w", hc.ID, err)
		}
		if err := checkMemFullPct(hc.MemFullPct); err != nil {
			return nil, fmt.Errorf("config: hotel %q: %w", hc.ID, err)
		}
		k, err := os.ReadFile(hc.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("hotel %s key: %w", hc.ID, err)
		}
		if hc.Concurrency <= 0 {
			hc.Concurrency = 16
		}
		installer, err := loadInstallSigner(hc)
		if err != nil {
			return nil, err
		}
		h := newHotel(hc, strings.TrimSpace(string(k)))
		if installer != nil {
			h.installer = installer
			log.Printf("config: hotel %s: broker installs its hotel key into the guest, signer %s", hc.ID, installSignerPublicB64(installer))
		}
		if err := b.addHotel(h); err != nil {
			return nil, err
		}
	}
	if len(c.PrewarmCatalogHotels) > 0 && !c.PrewarmCatalog {
		return nil, errors.New("config: prewarm_catalog_hotels needs \"prewarm_catalog\": true (the list only narrows it)")
	}
	for _, id := range c.PrewarmCatalogHotels {
		if b.hotelByID(id) == nil {
			return nil, fmt.Errorf("config: prewarm_catalog_hotels entry %q is not a hotel in hotels", id)
		}
	}
	if len(optedIn) > 0 {
		b.noteRequireAttestation(strings.Join(optedIn, ", "))
	}
	for _, gc := range c.Guests {
		if c.MinerEnrollKeySHA256 != "" && (strings.EqualFold(c.MinerEnrollKeySHA256, gc.KeySHA256) || strings.EqualFold(c.MinerEnrollKeySHA256, gc.NextKeySHA256) || strings.EqualFold(c.MinerEnrollKeySHA256, gc.ViewTokenSHA256)) {
			return nil, errors.New("config: miner enrollment key must differ from guest keys and view tokens")
		}
		if c.OperatorReadKeySHA256 != "" && (strings.EqualFold(c.OperatorReadKeySHA256, gc.KeySHA256) || strings.EqualFold(c.OperatorReadKeySHA256, gc.NextKeySHA256) || strings.EqualFold(c.OperatorReadKeySHA256, gc.ViewTokenSHA256)) {
			return nil, errors.New("config: operator read key must differ from guest keys and view tokens")
		}
		if c.MeterKeySHA256 != "" && (strings.EqualFold(c.MeterKeySHA256, gc.KeySHA256) || strings.EqualFold(c.MeterKeySHA256, gc.NextKeySHA256) || strings.EqualFold(c.MeterKeySHA256, gc.ViewTokenSHA256)) {
			return nil, errors.New("config: meter key must differ from guest keys and view tokens")
		}
		if gc.ID == "" {
			return nil, errors.New("config: a guest has no id (rooms with no broker_guest label would be its own)")
		}
		if b.guests[gc.ID] != nil {
			return nil, fmt.Errorf("config: guest id %q appears twice", gc.ID)
		}
		if gc.Policy != nil {
			if err := gc.Policy.validate(); err != nil {
				return nil, fmt.Errorf("config: guest %q: %w", gc.ID, err)
			}
		}
		g := &guestState{cfg: gc, limits: gc.guestLimits}
		g.limits.Hotels = append([]string(nil), gc.Hotels...)
		b.guests[gc.ID] = g
		if gc.KeySHA256 != "" {
			k := strings.ToLower(gc.KeySHA256)
			if other := b.byKey[k]; other != nil {
				return nil, fmt.Errorf("config: guests %q and %q share one key hash", other.cfg.ID, gc.ID)
			}
			b.byKey[k] = g
		}
		if gc.NextKeySHA256 != "" {
			k := strings.ToLower(gc.NextKeySHA256)
			if raw, err := hex.DecodeString(k); err != nil || len(raw) != sha256.Size {
				return nil, fmt.Errorf("config: guest %q: next_key_sha256 must be a SHA-256 hex digest", gc.ID)
			}
			if gc.KeySHA256 == "" {
				return nil, fmt.Errorf("config: guest %q: next_key_sha256 needs key_sha256 (it is a rotation, not a first key)", gc.ID)
			}
			if strings.EqualFold(k, gc.KeySHA256) {
				return nil, fmt.Errorf("config: guest %q: next_key_sha256 equals key_sha256", gc.ID)
			}
			if strings.EqualFold(k, c.OperatorKeySHA256) {
				return nil, fmt.Errorf("config: guest %q: next_key_sha256 must differ from the operator key", gc.ID)
			}
			if other := b.byKey[k]; other != nil {
				return nil, fmt.Errorf("config: guests %q and %q share one key hash", other.cfg.ID, gc.ID)
			}
			b.byKey[k] = g
		}
	}
	if err := c.AMDVerifier.validate(); err != nil {
		return nil, fmt.Errorf("config: amd_verifier: %w", err)
	}
	if err := c.ACMEDNS.validate(); err != nil {
		return nil, fmt.Errorf("config: acme_dns: %w", err)
	}
	for _, h := range b.hotelList() {
		if r := h.cfg.ReservedFor; r != "" && b.guests[r] == nil {
			return nil, fmt.Errorf("config: hotel %q is reserved_for unknown guest %q", h.cfg.ID, r)
		}
		if h.cfg.LentFrom != "" || h.cfg.LentReportID != "" {
			return nil, fmt.Errorf("config: hotel %q: lent_from and lent_report_id are set by PATCH {\"lend\": true} and kept in state_dir, not in the config file", h.cfg.ID)
		}
		h.roomsUnchecked = true
	}
	// The lend state in state_dir wins over reserved_for in the config file.
	if err := b.loadConfigLends(); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if err := b.loadAllowances(); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if err := b.loadUsageMeter(); err != nil {
		return nil, fmt.Errorf("usage meter: %w", err)
	}
	return b, nil
}

// ---------------------------------------------------------------- hotel calls

func (h *hotel) do(ctx context.Context, method, path string, query url.Values, body []byte, timeout time.Duration) (int, http.Header, []byte, error) {
	return h.doBase(ctx, h.cfg.API, method, path, query, body, timeout)
}

func (h *hotel) doBase(ctx context.Context, base, method, path string, query url.Values, body []byte, timeout time.Duration) (int, http.Header, []byte, error) {
	return h.doHeaders(ctx, base, method, path, query, body, timeout, nil)
}

// doHeaders is doBase with extra request headers (the guest id of
// guestcalls.go).
func (h *hotel) doHeaders(ctx context.Context, base, method, path string, query url.Values, body []byte, timeout time.Duration, extra http.Header) (int, http.Header, []byte, error) {
	status, hdr, out, _, err := h.doHeadersMax(ctx, base, method, path, query, body, timeout, extra, answerRead{})
	return status, hdr, out, err
}

// errAnswerTooLarge is a hotel answer longer than its caller reads (AB#752).
var errAnswerTooLarge = errors.New("the hotel answer is over its size limit")

// answerRead bounds one answer read (AB#752): at most maxBytes (0: no limit),
// and, with a pool, only once the answer's size is reserved in it for owner.
type answerRead struct {
	noRedirect bool // one destination only; no redirect or cookie replay
	maxBytes   int64
	pool       *answerPool
	owner      string
}

// doHeadersMax is doHeaders under an answerRead. A longer answer is an error,
// never a cut-off body to parse. The release it returns gives the reserved
// bytes back; the caller calls it once it no longer holds the body.
func (h *hotel) doHeadersMax(ctx context.Context, base, method, path string, query url.Values, body []byte, timeout time.Duration, extra http.Header, lim answerRead) (int, http.Header, []byte, func(), error) {
	noop := func() {}
	if err := h.keyedCallErr(base); err != nil {
		return 0, nil, nil, noop, err
	}
	u := base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, noop, err
	}
	for k, v := range extra {
		req.Header[k] = v
	}
	req.Header.Set("Authorization", "Bearer "+h.key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Room calls (/v1/...) take a data connection slot (hotelconns.go); the
	// /room/... calls (attestation, receipts, escape nonce) go to the Health
	// port, which has its own connections, and are not gated. The slot is held
	// until the body below is read and closed (defers run last in, first out).
	if !strings.HasPrefix(path, "/room/") {
		releaseConn, err := h.conns.acquire(ctx, h.cfg.ID)
		if err != nil {
			return 0, nil, nil, noop, err
		}
		defer releaseConn()
	}
	client := h.client
	if lim.noRedirect {
		copy := *client
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		copy.Jar = nil
		client = &copy
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, noop, err
	}
	defer resp.Body.Close()
	var reader io.Reader = resp.Body
	release := noop
	if lim.maxBytes > 0 {
		if resp.ContentLength > lim.maxBytes {
			return 0, nil, nil, noop, errAnswerTooLarge
		}
		reader = io.LimitReader(resp.Body, lim.maxBytes+1)
		if lim.pool != nil {
			size := lim.maxBytes // no length given: the most it may be
			if resp.ContentLength >= 0 {
				size = resp.ContentLength
			}
			if release, err = lim.pool.reserve(ctx, lim.owner, size); err != nil {
				return 0, nil, nil, noop, err
			}
		}
	}
	var out []byte
	if lim.maxBytes > 0 && resp.ContentLength >= 0 {
		// One buffer of the stated length: ReadAll would grow to about twice it.
		out = make([]byte, resp.ContentLength)
		_, err = io.ReadFull(reader, out)
	} else {
		out, err = io.ReadAll(reader)
	}
	if err != nil {
		release() // the caller gets no body to hold
		release = noop
	} else if lim.maxBytes > 0 && int64(len(out)) > lim.maxBytes {
		release()
		return 0, nil, nil, noop, errAnswerTooLarge
	}
	if err == nil && resp.StatusCode < 500 {
		// The hotel answers room calls. syncHotel keeps it "answering" while
		// these continue, even when its health endpoint is slow under load.
		h.lastAnswer.Store(time.Now().UnixNano())
	}
	return resp.StatusCode, resp.Header, out, release, err
}

func (h *hotel) getJSON(ctx context.Context, base, path string, query url.Values, v any) error {
	if err := h.keyedCallErr(base); err != nil {
		return err
	}
	u := base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("Authorization", "Bearer "+h.key)
	resp, err := h.ctl.Do(req) // its own connections: a guest's execs cannot starve the sync loop
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// ---------------------------------------------------------------- grid

func (h *hotel) resize(slots int) {
	if slots <= 0 || slots == h.slots {
		return
	}
	grid := make([]*room, slots)
	for _, r := range h.grid {
		if r != nil && r.slot >= 0 && r.slot < slots {
			grid[r.slot] = r
		} else if r != nil {
			r.slot = -1
		}
	}
	h.grid, h.slots = grid, slots
}

func (h *hotel) place(r *room) {
	r.slot = -1
	for i, x := range h.grid {
		if x == nil {
			h.grid[i], r.slot = r, i
			return
		}
	}
}

func (b *broker) release(h *hotel, r *room) {
	if r.uuid != "" && b.byUUID[r.uuid] == r {
		delete(b.byUUID, r.uuid)
		b.markDirty()
	}
	h.release(r)
}

func (h *hotel) release(r *room) {
	if r.slot >= 0 && r.slot < len(h.grid) && h.grid[r.slot] == r {
		h.grid[r.slot] = nil
	}
	r.slot = -1
	if r.hid != "" && h.rooms[r.hid] == r {
		delete(h.rooms, r.hid)
	}
}

func (h *hotel) used() int { return len(h.rooms) + h.creating + h.queued }

// pick a hotel at random among the hotels that pl allows. The weight is the
// free rooms times the hotel's headroom (placement.go). With a guest policy
// and no tier set, the preferred hotels come first: the allowed hotels are a
// candidate only when no preferred hotel has a free room (capacity.go).
// Caller holds b.mu.
func (b *broker) pick(exclude map[*hotel]bool, pl placement) *hotel {
	mb := b.minerBudgetNow() // the miner caps (placement.go), read once
	if pl.policy != nil && pl.tier == "" {
		for _, t := range []string{tierPrefer, tierAllow} {
			tp := pl
			tp.tier = t
			if h := b.pickIn(exclude, tp, mb); h != nil {
				return h
			}
		}
		return nil
	}
	return b.pickIn(exclude, pl, mb)
}

// pickIn is pick inside one candidate set.
func (b *broker) pickIn(exclude map[*hotel]bool, pl placement, mb *minerBudget) *hotel {
	now := time.Now()
	hotels := b.hotelList()
	total := 0.0
	weight := make([]float64, len(hotels))
	for i, h := range hotels {
		if exclude[h] || !pl.allows(h) || !b.diskFits(h, pl.diskGiB) {
			continue
		}
		if f := b.admissibleFreeIn(h, now, mb); f > 0 {
			weight[i] = h.weight(f)
			total += weight[i]
		}
	}
	total = b.preferWarm(hotels, weight, total, pl.image, pl.guest)
	if total <= 0 {
		return nil
	}
	n := rand.Float64() * total
	for i, w := range weight {
		if w > 0 && n < w {
			return hotels[i]
		}
		n -= w
	}
	for i := len(weight) - 1; i >= 0; i-- { // rounding: the last eligible hotel
		if weight[i] > 0 {
			return hotels[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------- HTTP helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (b *broker) guestFromKey(r *http.Request) *guestState {
	a := r.Header.Get("Authorization")
	if len(a) < 8 || !strings.EqualFold(a[:7], "bearer ") {
		return nil
	}
	return b.byKey[sha(strings.TrimSpace(a[7:]))]
}

// downSince is when the hotel went down, for the hotel lists; nil while up.
func downSince(h *hotel) any {
	if h.ok || h.downSince.IsZero() {
		return nil
	}
	return h.downSince.UTC().Format(time.RFC3339)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// ---------------------------------------------------------------- scatter

type createResult struct {
	status int
	header http.Header
	body   []byte
	doc    map[string]any
	// lost: hotels that got the create but never answered. Each may hold a
	// room this guest does not know about; handleCreate reaps them.
	lost []*hotel
	// sent: the create bytes the hotel that answered 202 received. createOne
	// sends one slice on every attempt, so these are the bytes of any retry
	// too; handleCreate returns them when the caller asks (returnCreateHeader).
	sent []byte
}

// returnCreateHeader asks a native single create to answer with the exact
// bytes sent to the hotel, as create_request_b64. A header, not a body field:
// a body field would have to be removed before the bytes are marshaled.
const returnCreateHeader = "X-Broker-Return-Create-Request"

// batchLabel marks every room of one create request, so the rooms a hotel
// started for a request whose answer was lost can be found and removed.
const batchLabel = "broker_batch"

// createOne places one room. body is the create as the hotel receives it,
// marshaled once per request; labels are its labels, for the delete by label
// tombstones (inflight.go); tRecv is when the guest request arrived.
func (b *broker) createOne(ctx context.Context, g *guestState, body []byte, labels map[string]any, tRecv time.Time, pl placement) createResult {
	tried := map[*hotel]bool{}
	var last createResult
	var lost []*hotel
	finish := func(r createResult) createResult { r.lost = lost; return r }
	asked, fellBack := pl, false
	wantTunables := createHasTunables(body)
	// size: read from body at the first retry of a metered create (allowance.go).
	var size *createSize
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 && createDeadlinePassed(pl) {
			// A retry (the first hotel refused or had no free connection)
			// would wait for a slot again past the create's own deadline.
			return finish(createTimedOut())
		}
		if attempt > 0 && size == nil && g.limits.Metered { // Metered is set once, at load
			s := createSizeOf(body)
			size = &s
		}
		b.mu.Lock()
		if size != nil {
			// A retry is a new admission for a metered guest (allowance.go).
			if e, retry := b.retryRefusalLocked(g, *size); e != nil {
				b.mu.Unlock()
				return finish(refusedRetry(last, e, retry))
			}
		}
		h := b.pick(tried, pl)
		if h == nil && !fellBack {
			// "placement": "prefer": the named hotels are down or full.
			if fb, ok := b.fallbackFor(pl); ok {
				pl, fellBack = fb, true
				h = b.pick(tried, pl)
			}
		}
		if h == nil {
			if last.status >= 500 {
				g.failed++
			}
			// A hotel would take the room but for its disk: sold out of disk,
			// not of rooms.
			// The disk extra is held on the hotel (holdDisk) from pick until
			// the room is known or the create ends (disk.go).
			diskOnly := last.status == 0 && b.pick(tried, pl.withoutDisk()) != nil
			b.mu.Unlock()
			if last.status != 0 {
				return finish(last)
			}
			if diskOnly {
				return finish(diskSoldOut(pl.diskGiB))
			}
			return finish(b.noRoom(asked))
		}
		tried[h] = true
		h.queued++
		g.queued++
		h.holdDisk(pl, 1)
		b.mu.Unlock()

		// Wait for a create slot. A create that waits too long moves to
		// another eligible hotel (placement.go).
		h = b.waitSlot(ctx, g, h, pl, tried)
		if h == nil {
			if ctx.Err() == nil && createDeadlinePassed(pl) {
				return finish(createTimedOut())
			}
			return finish(clientGone())
		}
		b.mu.Lock()
		// The hotel was admitted when the create was placed, but the create
		// may have queued for its slot past a refused or expired attestation,
		// or past a leave. Give the slot back and place the create again.
		if h.leaving || !b.admitted(h, time.Now()) {
			h.queued--
			g.queued--
			h.holdDisk(pl, -1)
			b.mu.Unlock()
			<-h.sem
			continue
		}
		gone, doomed := ctx.Err() != nil, b.tombstoned(g.cfg.ID, labels, tRecv)
		if gone || doomed {
			// The guest went away, or deleted this create by label, while it
			// waited for a slot: start no room.
			h.queued--
			g.queued--
			h.holdDisk(pl, -1)
			b.mu.Unlock()
			<-h.sem
			if gone {
				return finish(clientGone())
			}
			return finish(deletedDuringCreate())
		}
		b.mu.Unlock()
		tDispatch := time.Now()
		rm := &room{h: h, guest: g.cfg.ID, state: stCreating, since: tDispatch, diskGiB: pl.diskGiB}
		b.mu.Lock()
		h.queued--
		g.queued--
		h.creating++
		h.place(rm)
		b.mu.Unlock()

		// The hotel does not stop a create when the guest goes away. Keep the
		// call open, so the broker learns the room id and can delete the room.
		status, hdr, out, err := h.doHeaders(withCreateDeadline(context.WithoutCancel(ctx), pl), h.cfg.API, "POST", "/v1/sandboxes", nil, body, hotelCreateTimeout, ownerHeadersFrom(ctx))
		<-h.sem
		tDone := time.Now()

		b.mu.Lock()
		h.creating--
		h.holdDisk(pl, -1) // a started room counts in h.rooms from here (same b.mu hold)
		if errors.Is(err, errCreateDeadline) {
			// The create's deadline passed while it waited for a data
			// connection: never sent, so as errHotelBusy nothing to reap.
			h.release(rm)
			b.mu.Unlock()
			return finish(createTimedOut())
		}
		if errors.Is(err, errHotelBusy) {
			// No data connection came free in time (AB#819). The create was
			// never sent, so no room can exist there: not lost, nothing to
			// reap, and the hotel is not resting. Try another hotel.
			h.release(rm)
			b.mu.Unlock()
			last = createResult{status: 503, header: http.Header{"Retry-After": {strconv.Itoa(hotelBusyRetryAfter)}},
				doc: errDoc("sold_out", "hotel "+h.cfg.ID+hotelBusyMessage)}
			continue
		}
		var doc map[string]any
		if err == nil {
			_ = json.Unmarshal(out, &doc)
		}
		hid, _ := doc["id"].(string)
		started := err == nil && (status == 200 || status == 202) && hid != ""
		if started && (ctx.Err() != nil || b.tombstoned(g.cfg.ID, labels, tRecv)) {
			gone := ctx.Err() != nil
			h.release(rm)
			rm.hid, rm.id = hid, h.cfg.ID+"."+hid
			b.mu.Unlock()
			b.reapRoom(h, rm)
			if gone {
				return finish(clientGone())
			}
			return finish(deletedDuringCreate())
		}
		if started && wantTunables && !tunablesApplied(doc) {
			// The create carried per-room tunables and the hotel started the
			// room without reporting them (a room kit older than per-room
			// tunables ignores the field). That room did not run what was
			// asked: remove it and try another hotel, without resting this one.
			h.release(rm)
			rm.hid, rm.id = hid, h.cfg.ID+"."+hid
			b.mu.Unlock()
			b.reapRoom(h, rm)
			last = createResult{status: 409, doc: errDoc("tunables_unavailable",
				"hotel "+h.cfg.ID+" does not apply per-room tunables (room kit without them)")}
			continue
		}
		switch {
		case started:
			rm.hid, rm.id, rm.state, rm.since, rm.born = hid, h.cfg.ID+"."+hid, stRunning, tDone, tDone
			if old := h.rooms[hid]; old != nil && old != rm { // the sync loop saw it first
				b.release(h, old)
			}
			h.rooms[hid] = rm
			b.register(rm)
			b.usageMeter.seen(usageSightingOf(h, rm, createdResources(doc, body)), tDone) // the run's first reading (usage_meter.go)
			h.created++
			g.created++
			g.recent = append(g.recent, tDone)
			doc["id"] = rm.id
			doc["hotel"] = h.cfg.ID
			// A fallback create can still end on a named hotel (waitSlot,
			// or a retry once it recovers); only a room elsewhere is a fallback.
			fellBack = fellBack && !asked.ids[h.cfg.ID]
			if fellBack {
				doc["placement_fallback"] = true
			}
			tier := ""
			if pl.policy != nil {
				tier = pl.policy.tier(h)
				doc["placement_tier"] = tier
			}
			doc["isolation"] = isolationDoc(h, doc)
			if pl.snapshotRef != "" {
				doc["snapshot_id"] = pl.snapshotRef
			}
			queue, call := tDispatch.Sub(tRecv), tDone.Sub(tDispatch)
			h.lat.queue = append(h.lat.queue, ms(queue))
			h.lat.hotel = append(h.lat.hotel, ms(call))
			h.noteCreate(call)
			b.mu.Unlock()
			hdrs := http.Header{}
			copyRoomHeaders(hdrs, hdr)
			hdrs.Set("X-Broker-Hotel", h.cfg.ID)
			if fellBack {
				hdrs.Set("X-Broker-Fallback", "true")
			}
			if tier != "" {
				hdrs.Set("X-Broker-Placement-Tier", tier)
			}
			hdrs.Set("X-Broker-Queue-Ms", strconv.FormatFloat(ms(queue), 'f', 1, 64))
			hdrs.Set("X-Broker-Hotel-Ms", strconv.FormatFloat(ms(call), 'f', 1, 64))
			return finish(createResult{status: 202, header: hdrs, doc: doc, sent: body})
		case err == nil && status == 429:
			h.release(rm)
			h.rejected++
			ra, _ := strconv.Atoi(hdr.Get("Retry-After"))
			if ra <= 0 {
				ra = 2
			}
			h.backoffUntil = time.Now().Add(time.Duration(ra) * time.Second)
			b.mu.Unlock()
			last = createResult{status: 429, header: http.Header{"Retry-After": {strconv.Itoa(ra)}}, body: out}
			continue // try another hotel
		default:
			// The hotel could not start the room (for example a full bridge).
			// Rest it for a short time and try another hotel.
			rm.state, rm.since = stFailed, tDone
			// A 4xx usually means the request is wrong, not the hotel:
			// resting the hotel would turn one guest's bad input into a 503
			// for the next create of every guest. 401 and 403 are the
			// exception: the hotel rejects the broker's own key, so it is
			// broken for every guest and must rest.
			// image_pull_failed (502) is the guest's error only when the
			// registry says the image is missing or denied; a hotel that
			// cannot reach the registry (DNS, network, rate limit, disk) is
			// at fault and must rest so the create moves on.
			// With the guest's own registry login, the registry's rate limit is
			// the guest's quota, not the hotel's (AB#817).
			guestImage := status == 502 && errCodeOf(out) == "image_pull_failed" &&
				(guestImageFault(out) || (pl.registryAuth && registryRateLimited(out)))
			// A dedicated machine refusing a create the owner did not sign
			// (owner_signature_*) is the guest's error, not a broken hotel.
			ownerRefused := status == 403 && strings.HasPrefix(errCodeOf(out), "owner_signature_")
			if err != nil || (status >= 500 && !guestImage) || status == 401 || (status == 403 && !ownerRefused) {
				h.failed++
				h.backoffUntil = time.Now().Add(hotelFailBackoff)
			}
			// The hotel may hold a room it did not report: its answer was
			// lost, or it (or a proxy in front of it, as on a miner hotel)
			// failed after the room started. Its rooms of this request are
			// reaped before the guest gets an answer, so a create that moves
			// on to another hotel never leaves a second billed room. A 4xx or
			// the guest's own image fault is a refusal: no room was started.
			if err != nil || ((status < 400 || status >= 500) && !guestImage) {
				lost = append(lost, h)
				b.noteUncertainLocked(g) // counts for a metered guest until reaped (allowance.go)
			}
			if err != nil {
				last = createResult{status: 502, doc: map[string]any{"error": map[string]string{"code": "hotel_unreachable", "message": "hotel " + h.cfg.ID + " did not answer"}}}
			} else {
				last = createResult{status: status, body: out, header: http.Header{"X-Broker-Hotel": {h.cfg.ID}}}
			}
			if (status >= 400 && status < 500) || guestImage { // the request itself is wrong: no retry
				g.failed++
				b.mu.Unlock()
				return finish(last)
			}
			b.mu.Unlock()
			continue
		}
	}
	if last.status >= 500 {
		b.mu.Lock()
		g.failed++
		b.mu.Unlock()
	}
	return finish(last)
}

// createMany places count rooms for one request. The hotel's copy of the
// request is marshaled once: every room of a batch sends the same bytes (a
// 1 MiB body times count stays 1 MiB). A hotel that got a create and never
// answered may hold a room the guest does not know about: what this request
// did not receive is reaped.
func (b *broker) createMany(ctx context.Context, g *guestState, payload map[string]any, count int, tRecv time.Time, pl placement) []createResult {
	labels, _ := payload["labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
	}
	batchID := newUUID()
	labels[guestLabel] = g.cfg.ID
	labels[batchLabel] = batchID
	payload["labels"] = labels
	delete(payload, "count")
	pl.diskGiB = diskGiBOf(payload["resources"])
	body, _ := json.Marshal(payload)
	results := make([]createResult, count)
	if count == 1 {
		results[0] = b.createOne(ctx, g, body, labels, tRecv, pl)
		b.unreserve(g, 1)
	} else {
		// Batch: one create per room, all in parallel; the hotel semaphores bound the load.
		var wg sync.WaitGroup
		for i := 0; i < count; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = b.createOne(ctx, g, body, labels, tRecv, pl)
				b.unreserve(g, 1)
			}(i)
		}
		wg.Wait()
	}
	lost := map[*hotel]bool{}
	keep := map[*hotel]map[string]bool{}
	for _, res := range results {
		for _, h := range res.lost {
			lost[h] = true
		}
		if res.status == 202 {
			if hid, ok := res.doc["id"].(string); ok {
				if hotelID, id, ok := strings.Cut(hid, "."); ok {
					if h := b.hotelByID(hotelID); h != nil {
						if keep[h] == nil {
							keep[h] = map[string]bool{}
						}
						keep[h][id] = true
					}
				}
			}
		}
	}
	for h := range lost {
		if b.reapOrphans(h, g, batchID, keep[h]) {
			continue
		}
		// The failed hotel may still run a room of this request: the guest
		// is told, and the room stays recorded for the reaper (never adopted
		// as the guest's room) until its removal is confirmed.
		log.Printf("create of guest %s: rooms on failed hotel %s (batch %s) not confirmed removed; recorded for the reaper", g.cfg.ID, h.cfg.ID, batchID)
		for i := range results {
			if !slices.Contains(results[i].lost, h) {
				continue
			}
			if results[i].header == nil {
				results[i].header = http.Header{}
			}
			results[i].header.Add("X-Broker-Orphan-Cleanup", "pending; hotel="+h.cfg.ID)
			if results[i].doc != nil {
				results[i].doc["orphan_cleanup"] = map[string]any{"state": "pending", "hotel": h.cfg.ID}
			}
		}
	}
	b.settleUncertain(g, batchID, results, keep) // allowance.go
	return results
}

// reapOrphans removes the rooms of one create request that hotel h started
// although its answer never reached the broker. keep holds the hotel room
// ids this request did receive on h. The first pass runs before the guest
// gets its answer and its result is returned: true only when h confirmed
// every such room gone. Otherwise the request is recorded in h.unreaped and
// later passes retry in the background, then from the sync loop.
func (b *broker) reapOrphans(h *hotel, g *guestState, batchID string, keep map[string]bool) bool {
	if b.reapPass(h, g.cfg.ID, batchID, keep, 3*time.Second) {
		return true
	}
	b.mu.Lock()
	if h.unreaped == nil {
		h.unreaped = map[string]*unreapedBatch{}
	}
	ub := &unreapedBatch{guest: g.cfg.ID, keep: keep, busy: true}
	h.unreaped[batchID] = ub
	b.mu.Unlock()
	go func() {
		for _, wait := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second} {
			time.Sleep(wait)
			if b.reapPass(h, g.cfg.ID, batchID, keep, 10*time.Second) {
				b.reaped(h, batchID, ub)
				return
			}
		}
		b.mu.Lock()
		ub.busy = false
		b.mu.Unlock()
		log.Printf("orphan rooms of guest %s on hotel %s (batch %s) could not be reaped yet; the sync loop retries", g.cfg.ID, h.cfg.ID, batchID)
	}()
	return false
}

// reaped clears a recorded request once its rooms on h are confirmed gone.
// ub is the record the finished pass worked on: the pass ends (busy) and the
// record's fate is decided in one b.mu step, so no second pass starts in
// between.
func (b *broker) reaped(h *hotel, batchID string, ub *unreapedBatch) {
	b.mu.Lock()
	ub.busy = false
	if h.unreaped[batchID] != ub { // removed meanwhile
		b.mu.Unlock()
		return
	}
	if b.holdsLocked(h, batchID, ub, b.cleanupListedAtLocked(h, batchID)) {
		b.mu.Unlock() // a metered guest's lost create may still start its room (allowance.go)
		return
	}
	delete(h.unreaped, batchID)
	b.mu.Unlock()
	log.Printf("orphan rooms on hotel %s (batch %s) confirmed removed", h.cfg.ID, batchID)
}

// reapPass lists the rooms of one create request on h and deletes those the
// request did not receive. True when the list and every delete succeeded.
func (b *broker) reapPass(h *hotel, guestID, batchID string, keep map[string]bool, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	q := url.Values{}
	q.Add("label", batchLabel+"="+batchID)
	q.Add("label", guestLabel+"="+guestID)
	asked := time.Now() // when the list was asked for: a hold ends only on a list asked for after it (allowance.go)
	status, _, out, err := h.do(ctx, "GET", "/v1/sandboxes", q, nil, timeout)
	if err != nil || status != 200 {
		return false
	}
	listedAt := time.Now()
	var list struct {
		Sandboxes []struct {
			ID     string         `json:"id"`
			Labels map[string]any `json:"labels"`
		} `json:"sandboxes"`
	}
	if json.Unmarshal(out, &list) != nil {
		return false
	}
	b.mu.Lock()
	b.noteCleanupListLocked(h, batchID, asked) // allowance.go
	b.mu.Unlock()
	ok := true
	for _, s := range list.Sandboxes {
		if keep[s.ID] {
			continue
		}
		// A hotel that ignores the label filter (a miner hotel is
		// third-party code) must not get another request's rooms deleted.
		if s.Labels[batchLabel] != batchID || s.Labels[guestLabel] != guestID {
			continue
		}
		b.mu.Lock()
		turned := b.usageMeterOrphan(h, s.ID, guestID, listedAt, false) // not billable from here on (usage_meter.go)
		b.mu.Unlock()
		if turned { // durable before the delete, outside b.mu, bounded
			b.usageMeter.awaitDurable(usageTurnWait)
		}
		st, _, _, derr := h.do(waitForConnUntilDeadline(ctx), "DELETE", "/v1/sandboxes/"+url.PathEscape(s.ID), nil, nil, timeout)
		if derr != nil || (st != 204 && st != 404) {
			ok = false
			continue
		}
		b.mu.Lock()
		if rm := h.rooms[s.ID]; rm != nil { // the sync loop adopted it meanwhile
			b.release(h, rm)
		}
		b.noteOrphanRemovedLocked(h, batchID, s.ID) // counted once per room id (allowance.go)
		b.usageMeterOrphan(h, s.ID, guestID, listedAt, true)
		b.mu.Unlock()
		log.Printf("orphan room %s.%s of guest %s removed (create answer lost)", h.cfg.ID, s.ID, guestID)
	}
	return ok
}

// createHasTunables: the create body carries a non-null "tunables" object.
// The broker never reads or changes it; it goes to the one hotel that starts
// the room, in that room's own create body.
func createHasTunables(body []byte) bool {
	if !bytes.Contains(body, []byte(`"tunables"`)) {
		return false
	}
	var probe struct {
		Tunables json.RawMessage `json:"tunables"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return false
	}
	t := bytes.TrimSpace(probe.Tunables)
	return len(t) > 0 && !bytes.Equal(t, []byte("null"))
}

// tunablesApplied: the hotel's create answer reports the room's tunables as applied.
func tunablesApplied(doc map[string]any) bool {
	t, ok := doc["tunables"].(map[string]any)
	if !ok {
		return false
	}
	sha, _ := t["sha256"].(string)
	return t["status"] == "applied" && len(sha) == 64
}

// hotelFailBackoff rests a hotel after a failed room start.
const hotelFailBackoff = 10 * time.Second

// hotelCreateTimeout bounds one create call to a hotel. The hotel docker
// pull itself is 600s (sandbox_guest.py). A cold LFM3 pull on a sealed
// hotel (GHCR, about 1.2 GiB onto LUKS scratch) was dying as
// hotel_unreachable when this was 5 minutes. Prefetch is 30 minutes
// (images.go). 12 minutes covers the hotel pull plus start. A variable,
// not a constant, so a test can shorten it.
var hotelCreateTimeout = 12 * time.Minute

// nativeNetworkModes are the modes a native create may name. The hotel knows
// "public" (the old name of internet) and "none" as well (sandbox_api.py
// NETWORK_MODES), so those still pass through as before.
var nativeNetworkModes = map[string]bool{"internet": true, "deny_all": true, "allowlist": true, "public": true, "none": true}

// nativeNetwork is the network a native create sends the hotel. Same rule as
// the compat path (compatNetwork): a create that names no mode fails closed to
// deny_all. That covers no network, null, "", {} and an object whose mode is
// missing, null or "". Without this the hotel's own default (internet)
// applies, because sandbox_server.py reads a missing mode as "public" (AB#574).
// A mode the hotel does not know is refused before any hotel is asked. An
// object keeps its other fields; the hotel checks them.
func nativeNetwork(v any) (any, *apiErr) {
	switch n := v.(type) {
	case nil:
		return map[string]any{"mode": "deny_all", "allow": []any{}}, nil
	case string:
		if n == "" {
			return map[string]any{"mode": "deny_all", "allow": []any{}}, nil
		}
		if !nativeNetworkModes[n] {
			return nil, &apiErr{400, "invalid_network_mode", fmt.Sprintf("network must be internet, deny_all or allowlist, not %q", n)}
		}
		return n, nil
	case map[string]any:
		mode, ok := n["mode"]
		if !ok || mode == nil || mode == "" {
			out := make(map[string]any, len(n)+2)
			for k, x := range n {
				out[k] = x
			}
			out["mode"] = "deny_all"
			if out["allow"] == nil {
				out["allow"] = []any{}
			}
			return out, nil
		}
		if s, ok := mode.(string); !ok || !nativeNetworkModes[s] {
			return nil, &apiErr{400, "invalid_network_mode", fmt.Sprintf("network mode must be internet, deny_all or allowlist, not %v", mode)}
		}
		return n, nil
	}
	return nil, &apiErr{400, "invalid_network_mode", "network must be an object {\"mode\", \"allow\"} or a mode name"}
}

func (b *broker) handleCreate(w http.ResponseWriter, r *http.Request, g *guestState) {
	tRecv := time.Now()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, 400, "bad_body", "cannot read body")
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeErr(w, 400, "invalid_json", "request body is not JSON")
		return
	}
	// The object form {"image", "registry_auth"} names its reference inside:
	// the same refusal applies to it (AB#817).
	if ref := createImageRef(payload); ref != "" {
		if e := imageRefRefusal(ref, true); e != nil {
			writeErr(w, e.status, e.code, e.msg)
			return
		}
	}
	authErr, withAuth := createRegistryAuth(payload)
	if authErr != nil {
		writeErr(w, authErr.status, authErr.code, authErr.msg)
		return
	}
	if e := applyCatalogTemplate(payload); e != nil {
		writeErr(w, e.status, e.code, e.msg)
		return
	}
	net, nerr := nativeNetwork(payload["network"])
	if nerr != nil {
		writeErr(w, nerr.status, nerr.code, nerr.msg)
		return
	}
	payload["network"] = net
	deadline, derr := createDeadline(payload, tRecv)
	if derr != nil {
		writeErr(w, derr.status, derr.code, derr.msg)
		return
	}
	count := 1
	if c, ok := payload["count"].(float64); ok {
		count = int(c)
	}
	if count < 1 || count > 10000 {
		writeErr(w, 400, "invalid_count", "count must be between 1 and 10000")
		return
	}
	wantBytes := r.Header.Get(returnCreateHeader) == "1"
	if wantBytes && count != 1 {
		writeErr(w, 400, "create_request_batch_unsupported", "the create bytes can be returned for a single create only (count 1)")
		return
	}
	if wantBytes && withAuth {
		// The bytes hold the registry login: they never travel back.
		writeErr(w, 400, "create_request_with_registry_auth", "the create bytes are not returned for a create with registry_auth")
		return
	}
	// A metered guest: allowance, size and lifetime before any hotel call (allowance.go).
	if e, retry := b.meteredCreate(g, payload, count); e != nil {
		writeLimitErr(w, e, retry)
		return
	}
	pl, perr := b.placementFor(r.Context(), g, payload)
	if perr != nil {
		writeAPIErr(w, perr)
		return
	}
	pl.apply(payload)
	pl.image = createImageRef(payload)
	pl.deadline = deadline
	if e, retry := b.admitCreate(g, count, payload); e != nil {
		writeLimitErr(w, e, retry)
		return
	}
	results := b.createMany(withOwnerHeaders(r.Context(), r), g, payload, count, tRecv, pl)
	if count == 1 {
		if wantBytes && results[0].status == 202 && results[0].doc != nil {
			results[0].doc["create_request_b64"] = base64.StdEncoding.EncodeToString(results[0].sent)
		}
		b.finishCreate(w, results[0], tRecv)
		return
	}
	var docs []any
	errs := map[string]int{}
	for _, res := range results {
		if res.status == 202 {
			docs = append(docs, res.doc)
			continue
		}
		code := strconv.Itoa(res.status)
		if e, ok := res.doc["error"].(map[string]string); ok {
			code += " " + e["code"]
		}
		errs[code]++
	}
	status := 202
	if len(docs) == 0 {
		status = results[0].status
		if ra := results[0].header.Get("Retry-After"); status == 503 && ra != "" {
			w.Header().Set("Retry-After", ra) // sold_out: no hotel connection (AB#819)
		} else if e, _ := results[0].doc["error"].(map[string]string); status == 429 && e["code"] == "disk_sold_out" {
			w.Header().Set("Retry-After", strconv.Itoa(diskSoldOutRetryAfter))
		} else if status == 429 {
			w.Header().Set("Retry-After", "5")
		}
	}
	writeJSON(w, status, map[string]any{"sandboxes": docs, "count": len(docs), "errors": errs})
}

func (b *broker) finishCreate(w http.ResponseWriter, res createResult, tRecv time.Time) {
	for k, v := range res.header {
		w.Header()[k] = v
	}
	if res.status == 202 {
		q, _ := strconv.ParseFloat(res.header.Get("X-Broker-Queue-Ms"), 64)
		c, _ := strconv.ParseFloat(res.header.Get("X-Broker-Hotel-Ms"), 64)
		over := ms(time.Since(tRecv)) - q - c
		w.Header().Set("X-Broker-Overhead-Ms", strconv.FormatFloat(over, 'f', 2, 64))
		b.mu.Lock()
		if h := b.hotelByID(res.header.Get("X-Broker-Hotel")); h != nil {
			h.lat.overhead = append(h.lat.overhead, over)
		}
		b.mu.Unlock()
	}
	if res.doc != nil {
		writeJSON(w, res.status, res.doc)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.status)
	_, _ = w.Write(res.body)
}

// ---------------------------------------------------------------- route

// terminalsRefused says why the terminal routes of room bid stay closed, or
// "" when they may go on to its hotel. The broker cannot see which room kit a
// hotel runs, so only operator hotels named in terminal_hotels pass. A miner
// runs a kit the operator did not install, so a miner hotel never passes.
func (b *broker) terminalsRefused(bid string) string {
	hotelID, _, _ := strings.Cut(bid, ".")
	if h := b.hotelByID(hotelID); h != nil && isMinerHotel(h) {
		return "room terminals are disabled on miner hotels; use exec"
	}
	if !slices.Contains(b.cfg.TerminalHotels, hotelID) {
		return "room terminals are disabled on this hotel (not on the broker terminal allowlist); use exec"
	}
	return ""
}

// isMinerHotel reports whether an SN94 miner runs h. The hotkey is the mark;
// the miner label and the id prefix of miner joins (miner-<hex>) also count,
// so a miner machine joined without a hotkey stays closed.
func isMinerHotel(h *hotel) bool {
	return h.cfg.MinerHotkey != "" || h.labels()["miner"] == "true" || strings.HasPrefix(h.cfg.ID, "miner-")
}

func (b *broker) handleRoom(w http.ResponseWriter, r *http.Request, g *guestState, rest string) {
	tRecv := time.Now()
	bid, tail, _ := strings.Cut(rest, "/")
	// The tail is decoded and goes to the hotel by string concatenation, so a
	// decoded "?" or "#" would turn the rest into a query or fragment there and
	// slip past the gates below ("desktop%3F" reaches the hotel's /desktop).
	// No hotel route works with one, so refuse it before any gate.
	if strings.ContainsAny(tail, "?#") {
		writeErr(w, 400, "invalid_path", "a sandbox path cannot contain an encoded ? or #")
		return
	}
	// The gates below key on the first tail segment without any ";params":
	// the hotel's router (urlparse) drops ";params" from the last segment, so
	// "desktop;x" or "terminals;x" reaches the same hotel route as the bare name.
	gate, _, _ := strings.Cut(tail, "/")
	gate, _, _ = strings.Cut(gate, ";")
	// Room terminals open only on hotels known to run a package where a
	// terminal line goes through the runtime's exec (B154).
	if gate == "terminals" {
		if why := b.terminalsRefused(bid); why != "" {
			writeErr(w, 403, "terminals_disabled", why)
			return
		}
	}
	// The hotel's own desktop routes stay closed on every hotel: the broker
	// pumps a WebSocket only for terminals (terminal_ws.go), and the
	// availability answer names the hotel's internal address. A desktop runs
	// over exec. This sits before the WebSocket branch below on purpose.
	if gate == "desktop" {
		writeErr(w, 403, "desktop_disabled", "room desktop routes are disabled on every hotel; drive a desktop over exec")
		return
	}
	// The tail goes to the hotel as part of its path. A dot segment would
	// climb out of this room if anything between us and the hotel normalized it.
	for _, seg := range strings.Split(tail, "/") {
		if seg == "." || seg == ".." {
			writeErr(w, 400, "invalid_path", "a sandbox path cannot contain . or .. segments")
			return
		}
	}
	// A background exec's result outlives its room (AB#733): read and stop it
	// by the guest and room stored on the exec, not the live room list.
	if strings.HasPrefix(tail, "execs/") && (r.Method == "GET" || r.Method == "DELETE") && !strings.Contains(strings.TrimPrefix(tail, "execs/"), "/") {
		b.nativeExecPoll(w, r, g, bid, strings.TrimPrefix(tail, "execs/"))
		return
	}
	hotelID, hid, ok := strings.Cut(bid, ".")
	h := b.hotelByID(hotelID)
	// A room of this guest that ended answers 410 with why (ended.go); a
	// wrong id or another guest's room stays 404. After the exec poll above,
	// so exec results of a gone room still read.
	if !ok || h == nil {
		if !b.writeGone(w, g, bid) {
			writeErr(w, 404, "sandbox_not_found", "no sandbox "+bid)
		}
		return
	}
	b.mu.Lock()
	rm := h.rooms[hid]
	owned := rm != nil && rm.guest != "" && rm.guest == g.cfg.ID // an unlabeled room belongs to no guest
	b.mu.Unlock()
	if !owned {
		if !b.writeGone(w, g, bid) {
			writeErr(w, 404, "sandbox_not_found", "no sandbox "+bid)
		}
		return
	}
	// The proof lives on the guest's receipts front, not its sandbox API.
	// Resolve the route's room under this guest before selecting that endpoint.
	if gate == "release-proof" {
		b.handleRoomReleaseProof(w, r, g, h, hid, tail)
		return
	}
	// A terminal WebSocket goes to the hotel as a raw byte pump (terminal_ws.go),
	// after the allowlist and ownership checks above. A plain GET on the same
	// path takes the normal route below.
	if isWebSocketUpgrade(r) && terminalWSTail(tail) {
		b.proxyTerminalWS(w, r, h, hid, bid, tail)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 256<<20+1))
	if len(body) > 256<<20 {
		// Forwarding the first 256 MiB would write a short file and answer 200.
		writeErr(w, 413, "request_too_large", "the body is over 256 MiB")
		return
	}
	// A metered guest: a lifetime route is a new admission (allowance.go).
	body, pass := b.meteredRoomRoute(w, r, g, h, hid, gate, tail, body)
	if !pass {
		return
	}
	if r.Method == "POST" && tail == "snapshot" {
		b.roomSnapshot(w, r, g, h, hid, body)
		return
	}
	if b.routeNativeExec(w, r, g, rm, bid, tail, body) {
		return
	}
	// Hotel ids (nc-sealed.sbx_…) proxy the body as-is. Reject a string cmd
	// here so the hotel path matches the client UUID path and the docs.
	if r.Method == "POST" && tail == "exec" {
		if err := requireExecCmdList(body); err != nil {
			writeErr(w, 400, "invalid_exec", err.Error())
			return
		}
	}
	path := "/v1/sandboxes/" + url.PathEscape(hid)
	if tail != "" {
		path += "/" + tail
	}
	timeout := 2 * time.Minute
	if strings.HasSuffix(tail, "exec") || strings.HasSuffix(tail, "wait") {
		timeout = 20 * time.Minute
		// A long exec must not lose its answer: wait for its own limit plus a margin.
		var req struct {
			Timeout float64 `json:"timeout_seconds"`
		}
		if json.Unmarshal(body, &req) == nil && req.Timeout > 0 {
			if t := time.Duration(req.Timeout)*time.Second + 2*time.Minute; t > timeout {
				timeout = t
			}
		}
	}
	var bodyArg []byte
	if r.Method != "GET" && r.Method != "DELETE" {
		bodyArg = body
	}
	tDispatch := time.Now()
	callCtx := r.Context()
	if r.Method == "DELETE" && tail == "" {
		// A room delete that gave up would leave the room running on a full
		// hotel: it waits for a connection until its deadline, as before.
		callCtx = waitForConnUntilDeadline(callCtx)
	}
	status, hdr, out, err := h.do(callCtx, r.Method, path, r.URL.Query(), bodyArg, timeout)
	// AB#741: the same split as a create (X-Broker-Queue-Ms, X-Broker-Hotel-Ms) on
	// every answer that went to the hotel, failures included, so a burst of execs
	// can be split into broker and hotel time per request. Here the "queue" is the
	// broker's own time before the hotel call (reading the body, the room lookup);
	// this path has no wait slot. An answer without them was refused by the broker
	// before the hotel was asked.
	setBrokerTiming(w.Header(), h.cfg.ID, tDispatch.Sub(tRecv), time.Since(tDispatch))
	if err != nil {
		writeHotelErr(w, h, err)
		return
	}
	if r.Method == "DELETE" && tail == "" && (status == 204 || status == 404) {
		b.mu.Lock()
		live := rm.state == stRunning // not already marked gone by the sync loop
		if live {
			rm.state, rm.vanished = stDeleting, time.Now()
		}
		rm.deleteSent = true
		b.usageMeter.end(rm.id, time.Now(), status == 204 && live) // the run's ended reading (usage_meter.go)
		b.mu.Unlock()
	}
	for _, k := range []string{"Content-Type", "Content-Range", "Content-Length", "Retry-After", "Accept-Ranges"} {
		if v := hdr.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	copyRoomHeaders(w.Header(), hdr)
	// Signed receipts must reach the guest byte for byte: no id rewrite there.
	if strings.HasPrefix(hdr.Get("Content-Type"), "application/json") && tail != "receipts" {
		out = bytes.ReplaceAll(out, []byte(`"`+hid+`"`), []byte(`"`+bid+`"`))
		if tail == "exec" && status == 200 {
			out = truncateExecJSON(out)
		}
		w.Header().Del("Content-Length")
		// The room document itself says what its placement isolates.
		if r.Method == "GET" && tail == "" && status == 200 {
			var doc map[string]any
			if json.Unmarshal(out, &doc) == nil {
				doc["hotel"] = h.cfg.ID
				doc["isolation"] = isolationDoc(h, doc)
				if re, err := json.Marshal(doc); err == nil {
					out = re
				}
			}
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

// setBrokerTiming names the hotel and splits the broker's time into the wait
// before the hotel call (queue) and the hotel call itself, in milliseconds.
func setBrokerTiming(dst http.Header, hotelID string, queue, call time.Duration) {
	dst.Set("X-Broker-Hotel", hotelID)
	dst.Set("X-Broker-Queue-Ms", strconv.FormatFloat(ms(queue), 'f', 1, 64))
	dst.Set("X-Broker-Hotel-Ms", strconv.FormatFloat(ms(call), 'f', 1, 64))
}

// copyRoomHeaders passes the hotel's X-Room-* headers (for example the signed
// receipt of a sealed hotel, X-Room-Receipt) to the guest unchanged.
func copyRoomHeaders(dst, src http.Header) {
	for k, v := range src {
		if strings.HasPrefix(k, "X-Room-") {
			dst[k] = v
		}
	}
}

// requireExecCmdList enforces the published contract: cmd / command must be a
// non-empty list of non-empty strings. A shell string is refused.
func requireExecCmdList(raw []byte) error {
	var req map[string]any
	if json.Unmarshal(raw, &req) != nil {
		return fmt.Errorf("request body is not JSON")
	}
	cmd := req["command"]
	if cmd == nil {
		cmd = req["cmd"]
	}
	if cmd == nil {
		return fmt.Errorf("cmd is required")
	}
	list, ok := cmd.([]any)
	if !ok || len(list) == 0 {
		return fmt.Errorf("cmd must be a non-empty list of strings")
	}
	for _, x := range list {
		s, ok := x.(string)
		if !ok || s == "" {
			return fmt.Errorf("cmd must be a non-empty list of strings")
		}
	}
	return nil
}

// execOutputCapBytes is the maximum stdout/stderr the broker returns on an
// exec. Matches the hotel guest cap; a hotel that forgets to truncate is
// clipped here and marked truncated.
const execOutputCapBytes = 16 << 20

// clipExecDoc caps stdout/stderr on an exec JSON object and sets truncated
// when either stream was longer than the cap.
func clipExecDoc(doc map[string]any) {
	for _, k := range []string{"stdout", "stderr"} {
		s, ok := doc[k].(string)
		if !ok {
			continue
		}
		b := []byte(s)
		if len(b) > execOutputCapBytes {
			doc[k] = string(b[:execOutputCapBytes])
			doc["truncated"] = true
		}
	}
}

// truncateExecJSON caps stdout/stderr in an exec JSON answer and sets
// truncated when either stream was longer than the cap.
func truncateExecJSON(out []byte) []byte {
	var doc map[string]any
	if json.Unmarshal(out, &doc) != nil {
		return out
	}
	before, _ := json.Marshal(doc)
	clipExecDoc(doc)
	re, err := json.Marshal(doc)
	if err != nil || bytes.Equal(before, re) {
		return out
	}
	return re
}

// handleHotelDoc passes a hotel's attestation or receipt chain to a guest:
// GET /v1/hotels/<id>/attestation and GET /v1/hotels/<id>/receipts.
// The hotel chain is one list per boot. A guest sees only receipts for rooms
// they have owned. An ops key sees the whole chain.
func (b *broker) handleHotelDoc(w http.ResponseWriter, r *http.Request, rest string, g *guestState) {
	id, doc, _ := strings.Cut(rest, "/")
	h := b.hotelByID(id)
	if h != nil && doc == "attest" && r.Method == "POST" {
		b.handleHotelAttest(w, r, h, g)
		return
	}
	if h == nil || (doc != "attestation" && doc != "receipts") || r.Method != "GET" {
		writeErr(w, 404, "route_not_found", "no such hotel document")
		return
	}
	// The receipt chain of a hotel outside the guest's list (for example one
	// dedicated to another guest) is not this guest's, ops included. The
	// attestation stays public: it proves the machine, not anyone's work.
	if doc == "receipts" && !g.limitsAllow(b, h.cfg.ID) {
		writeErr(w, 404, "route_not_found", "no such hotel document")
		return
	}
	if doc == "receipts" && !g.cfg.Ops {
		// Walk the hotel chain so a busy hotel's oldest page does not hide
		// this guest's newer receipts (CONST / Affinities empty /receipts).
		filtered, ferr := b.filterGuestHotelReceipts(r.Context(), h, g.cfg.ID, r.URL.Query())
		if ferr != nil {
			writeErr(w, 502, "receipts_unreadable", "hotel receipt chain could not be filtered")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Del("Content-Length")
		w.WriteHeader(200)
		_, _ = w.Write(filtered)
		return
	}
	status, hdr, out, err := h.doBase(r.Context(), h.cfg.Health, "GET", "/room/"+doc, r.URL.Query(), nil, time.Minute)
	if err != nil {
		writeHotelErr(w, h, err)
		return
	}
	if status == 200 && doc == "receipts" {
		after, _ := strconv.Atoi(r.URL.Query().Get("after"))
		b.archiveHotelPage(h, after, out)
	}
	if v := hdr.Get("Content-Type"); v != "" {
		w.Header().Set("Content-Type", v)
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

// hotelAttestBodyMax caps POST /v1/hotels/<id>/attest. The body is 128 hex
// characters, plus for an Escape rd-claims-v1 report the receipt claims in
// escape_claims_b64 (the hotel takes up to 12 KiB of claims, about 2 KiB today).
const hotelAttestBodyMax = 20480

// handleHotelAttest passes POST /v1/hotels/<id>/attest to the hotel's
// POST /room/attest: a fresh SEV-SNP report whose REPORT_DATA is the 64
// bytes the caller sent. A hotel outside the guest's list answers 404, as
// for receipts. The body goes to the hotel unchanged and the hotel's JSON
// (status, body, Retry-After) comes back unchanged; the hotel validates.
func (b *broker) handleHotelAttest(w http.ResponseWriter, r *http.Request, h *hotel, g *guestState) {
	if !g.limitsAllow(b, h.cfg.ID) {
		writeErr(w, 404, "route_not_found", "no such hotel document")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, hotelAttestBodyMax))
	if err != nil {
		writeErr(w, 413, "body_too_large", "attest body over 20480 bytes")
		return
	}
	// "sandbox_id" asks for that room's signed create receipt too. Only a
	// room of this guest on this hotel: another guest's room is a 404, as on
	// the receipts route. The broker id <hotel>.<id> becomes the hotel's id.
	if body, err = b.attestRoom(body, h, g); err != nil {
		writeErr(w, 404, "room_not_found", err.Error())
		return
	}
	// Pass the guest id so the hotel rate-limits attest per guest, not per
	// hotel (shared hotels serve many Escape / capacity callers).
	status, hdr, out, err := h.doHeaders(
		r.Context(), h.cfg.Health, "POST", "/room/attest", nil, body, time.Minute,
		http.Header{guestHeader: {g.cfg.ID}},
	)
	if err != nil {
		writeHotelErr(w, h, err)
		return
	}
	for _, k := range []string{"Content-Type", "Retry-After"} {
		if v := hdr.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

// attestRoom checks the attest body's optional "sandbox_id" against the
// guest's rooms on h and rewrites it to the hotel's room id. A body without
// it, or that is not JSON, goes to the hotel unchanged (the hotel validates).
func (b *broker) attestRoom(body []byte, h *hotel, g *guestState) ([]byte, error) {
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return body, nil
	}
	raw, ok := doc["sandbox_id"]
	if !ok || raw == nil {
		return body, nil
	}
	id, _ := raw.(string)
	hid := strings.TrimPrefix(id, h.cfg.ID+".")
	if id == "" || !b.guestRoomIDs(g.cfg.ID, h.cfg.ID)[hid] {
		return nil, fmt.Errorf("no room %q of this guest on hotel %s", id, h.cfg.ID)
	}
	doc["sandbox_id"] = hid
	return json.Marshal(doc)
}

// ---------------------------------------------------------------- gather

// fanout asks every hotel in the guest's list. A hotel outside the list is
// not asked: it may hang, and its id and totals are not the guest's.
func (b *broker) fanout(ctx context.Context, g *guestState, path string, q url.Values) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range b.hotelList() {
		if !g.limitsAllow(b, h.cfg.ID) {
			continue
		}
		wg.Add(1)
		go func(h *hotel) {
			defer wg.Done()
			status, _, body, err := h.do(ctx, "GET", path, q, nil, 30*time.Second)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || status != 200 {
				out[h.cfg.ID] = json.RawMessage(`{"error":"unavailable"}`)
				return
			}
			out[h.cfg.ID] = body
		}(h)
	}
	wg.Wait()
	return out
}

func (b *broker) handleList(w http.ResponseWriter, r *http.Request, g *guestState) {
	q := r.URL.Query()
	q.Add("label", guestLabel+"="+g.cfg.ID)
	parts := b.fanout(r.Context(), g, "/v1/sandboxes", q)
	all := []map[string]any{}
	errs := map[string]string{}
	for hid, raw := range parts {
		var doc struct {
			Sandboxes []map[string]any `json:"sandboxes"`
			Error     any              `json:"error"`
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Error != nil {
			errs[hid] = "unavailable"
			continue
		}
		for _, s := range doc.Sandboxes {
			if id, ok := s["id"].(string); ok {
				s["id"] = hid + "." + id
			}
			s["hotel"] = hid
			if h := b.hotelByID(hid); h != nil {
				s["isolation"] = isolationDoc(h, s)
			}
			all = append(all, s)
		}
	}
	sort.Slice(all, func(i, j int) bool { return fmt.Sprint(all[i]["id"]) < fmt.Sprint(all[j]["id"]) })
	writeJSON(w, 200, map[string]any{"sandboxes": all, "count": len(all), "hotel_errors": errs})
}

func sumInto(dst map[string]any, src map[string]any) {
	for k, v := range src {
		switch x := v.(type) {
		case float64:
			d, _ := dst[k].(float64)
			dst[k] = d + x
		case map[string]any:
			sub, _ := dst[k].(map[string]any)
			if sub == nil {
				sub = map[string]any{}
				dst[k] = sub
			}
			sumInto(sub, x)
		}
	}
}

func (b *broker) handleQuota(w http.ResponseWriter, r *http.Request, g *guestState) {
	parts := b.fanout(r.Context(), g, "/v1/quota", nil)
	total := map[string]any{}
	hotels := map[string]any{}
	for hid, raw := range parts {
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil || doc["error"] != nil {
			hotels[hid] = "unavailable"
			continue
		}
		sumInto(total, map[string]any{"limits": doc["limits"], "usage": doc["usage"]})
		hotels[hid] = map[string]any{"limits": doc["limits"], "usage": doc["usage"]}
	}
	b.mu.Lock()
	mine := 0
	for _, h := range b.hotelList() {
		for _, rm := range h.rooms {
			if rm.guest == g.cfg.ID && rm.state == stRunning {
				mine++
			}
		}
	}
	lim := g.limits
	b.mu.Unlock()
	allowed := lim.Hotels
	if allowed == nil {
		allowed = []string{}
	}
	total["hotels"] = hotels
	total["guest"] = map[string]any{"id": g.cfg.ID, "running_sandboxes": mine, "max_rooms": lim.maxRooms(),
		"max_creates_per_minute": lim.MaxCreatesPerMinute, "default_sealed": lim.DefaultSealed, "allowed_hotels": allowed}
	writeJSON(w, 200, total)
}

// A hotel's /v1/usage prices its hours with an illustrative rate card (cathedral/sandbox_api.py
// Pricing), about 8x the list price on 21 Nov 2026 (AB#870). The broker holds no price, so a guest
// gets hours only: each hotel part keeps an allowlist of fields, and the answer says where prices are.
const usageCostNote = "not_priced_here"
const usagePriceDoc = "https://cathedral.computer/pricing/"

func usageHoursOnly(raw json.RawMessage) any {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil || doc == nil {
		return map[string]any{"error": "unavailable"}
	}
	if e, ok := doc["error"]; ok {
		return map[string]any{"error": e}
	}
	out := map[string]any{}
	if v, ok := doc["group_by"].(string); ok {
		out["group_by"] = v
	}
	if v, ok := doc["snapshot_gib_months"].(float64); ok {
		out["snapshot_gib_months"] = v
	}
	groups := map[string]any{}
	if gs, ok := doc["groups"].(map[string]any); ok {
		for name, gv := range gs {
			gm, ok := gv.(map[string]any)
			if !ok {
				continue
			}
			kept := map[string]any{}
			for _, k := range []string{"sandbox_hours", "vcpu_hours", "gib_hours"} {
				if v, ok := gm[k].(float64); ok {
					kept[k] = v
				}
			}
			groups[name] = kept
		}
	}
	out["groups"] = groups
	return out
}

func (b *broker) usageParts(r *http.Request, g *guestState) map[string]any {
	q := r.URL.Query()
	q.Add("label", guestLabel+"="+g.cfg.ID)
	parts := map[string]any{}
	for hid, raw := range b.fanout(r.Context(), g, "/v1/usage", q) {
		parts[hid] = usageHoursOnly(raw)
	}
	return parts
}

func (b *broker) handleUsage(w http.ResponseWriter, r *http.Request, g *guestState) {
	writeJSON(w, 200, map[string]any{"hotels": b.usageParts(r, g), "cost": usageCostNote, "price_doc": usagePriceDoc})
}

func (b *broker) handleBulkDelete(w http.ResponseWriter, r *http.Request, g *guestState) {
	q := r.URL.Query()
	if len(q["label"]) == 0 {
		writeErr(w, 400, "invalid_label", "bulk delete requires a label filter")
		return
	}
	// Creates in flight that match this filter are deleted too (inflight.go).
	b.mu.Lock()
	b.addTombstone(g.cfg.ID, q["label"], time.Now())
	b.mu.Unlock()
	q.Add("label", guestLabel+"="+g.cfg.ID)
	res := map[string]int{}
	claimBusy := false
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range b.hotelList() {
		if !g.limitsAllow(b, h.cfg.ID) { // a guest has no rooms outside its list
			continue
		}
		wg.Add(1)
		go func(h *hotel) {
			defer wg.Done()
			gone := b.bulkDeleteTargets(r.Context(), h, q) // sighted now, ended on success (usage_meter.go)
			status, busy := bulkDeleteFromHotel(r.Context(), h, q)
			if status >= 200 && status < 300 {
				b.usageMeterBulkDeleted(gone)
			}
			mu.Lock()
			res[h.cfg.ID] = status
			claimBusy = claimBusy || busy
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	if claimBusy {
		writeJSON(w, 409, map[string]any{"error": map[string]string{
			"code": "bulk_delete_claim_busy", "message": "bulk deletion may be incomplete after a room claim; retry it",
		}, "hotels": res})
		return
	}
	writeJSON(w, 200, map[string]any{"hotels": res})
}

// A claim's lifetime call is bounded at the hotel. Retry only its explicit
// refusal; another 409 can mean a permanent problem and must keep its status.
func bulkDeleteFromHotel(ctx context.Context, h *hotel, q url.Values) (int, bool) {
	deadline := time.Now().Add(12 * time.Second)
	sawClaimBusy := false
	for {
		status, _, body, err := h.do(waitForConnUntilDeadline(ctx), "DELETE", "/v1/sandboxes", q, nil, 30*time.Minute)
		if err != nil {
			if sawClaimBusy {
				return 409, true
			}
			return 502, false
		}
		if status != 409 || errCodeOf(body) != "bulk_delete_claim_busy" {
			return status, sawClaimBusy && (status < 200 || status >= 300)
		}
		sawClaimBusy = true
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 409, true
		}
		wait := min(100*time.Millisecond, remaining)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 409, true
		case <-timer.C:
		}
	}
}

// ---------------------------------------------------------------- stats

func pct(xs []float64) map[string]float64 {
	if len(xs) == 0 {
		return map[string]float64{"n": 0}
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	at := func(p float64) float64 { return s[int(p*float64(len(s)-1))] }
	return map[string]float64{"n": float64(len(s)), "p50": at(0.5), "p95": at(0.95), "p99": at(0.99), "max": s[len(s)-1]}
}

func (b *broker) handleStats(w http.ResponseWriter, r *http.Request, g *guestState) {
	if r.Method == "POST" && !g.cfg.Ops {
		writeErr(w, 403, "forbidden", "this key may not reset the broker counters")
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.Method == "POST" {
		for _, h := range b.hotelList() {
			h.created, h.failed, h.rejected, h.lat = 0, 0, 0, latencies{}
			h.conns.waits.Store(0)
			h.conns.refused.Store(0)
		}
		for _, x := range b.guests {
			x.created, x.failed, x.rejected = 0, 0, 0
		}
		writeJSON(w, 200, map[string]string{"reset": "ok"})
		return
	}
	hotels := []any{}
	for _, h := range b.hotelList() {
		running := 0
		for _, rm := range h.rooms {
			if rm.state == stRunning {
				running++
			}
		}
		hotels = append(hotels, map[string]any{
			"id": h.cfg.ID, "ok": h.ok, "drain": h.drain(), "sealed": h.cfg.Sealed, "slots": h.slots, "broker_running": running, "queued": h.queued, "creating": h.creating,
			"api_running": h.apiRunning, "api_deleting": h.apiDeleting, "containers": h.containers,
			"runtime": h.hotelRuntime(), "kernel_isolation": h.kernelIsolation,
			"cpu_pct": h.cpuPct, "mem_pct": h.memPct, "mem_gib": h.memGiB, "load1": h.load1, "mem_full": b.memFull(h), "mem_full_pct": b.memFullLimit(h),
			"created": h.created, "failed": h.failed, "rejected_429": h.rejected,
			"hotel_ms": pct(h.lat.hotel), "queue_ms": pct(h.lat.queue), "overhead_ms": pct(h.lat.overhead),
			"conns": h.conns.stats(),
		})
	}
	writeJSON(w, 200, map[string]any{"guest": g.cfg.ID, "created": g.created, "failed": g.failed, "rejected_429": g.rejected, "hotels": hotels})
}

// ---------------------------------------------------------------- sync loop

type healthDoc struct {
	Slots            int    `json:"slots"`
	SandboxesRunning *int   `json:"sandboxes_running"`
	Runtime          string `json:"runtime"`
	KernelIsolation  *bool  `json:"kernel_isolation"`
	Live             struct {
		CPU    *float64 `json:"host_cpu_pct"`
		MemPct float64  `json:"host_mem_used_pct"`
		MemGiB float64  `json:"host_mem_used_gib"`
		Load1  float64  `json:"load1"`
		// RoomDataPct: use of the scratch that holds the room disks (disk.go).
		RoomDataPct *float64 `json:"room_data_used_pct"`
	} `json:"live"`
}

func (b *broker) syncHotel(ctx context.Context, h *hotel) {
	b.syncGuestPin(ctx, h) // a guest_tls hotel: no keyed call before its TLS key is verified
	var hd healthDoc
	t0 := time.Now()
	herr := h.getJSON(ctx, h.cfg.Health, "/room/health", nil, &hd)
	healthMs := ms(time.Since(t0))
	var quota struct {
		Usage map[string]float64 `json:"usage"`
	}
	qerr := h.getJSON(ctx, h.cfg.API, "/v1/quota", nil, &quota)
	var list struct {
		Sandboxes []struct {
			ID     string            `json:"id"`
			State  string            `json:"state"`
			Labels map[string]string `json:"labels"`
			// A map, so a hotel that sends an odd field does not fail the list.
			Resources map[string]any `json:"resources"`
			// AB#864: end record inputs. EndReason is set by a hotel with
			// Change B on a listed room whose container died.
			ExpiresAt string `json:"expires_at"`
			EndReason string `json:"end_reason"`
		} `json:"sandboxes"`
		// AB#864 Change B: rooms the hotel ended lately, and when its API
		// started. A hotel without them sends neither.
		Ended []struct {
			ID        string `json:"id"`
			EndReason string `json:"end_reason"`
		} `json:"ended"`
		APIStartedAt string `json:"api_started_at"`
	}
	listAsked := time.Now() // a hold ends only on a list asked for after it (allowance.go)
	lerr := h.getJSON(ctx, h.cfg.API, "/v1/sandboxes", nil, &list)
	listedAt := time.Now()
	defer b.sampleProbation(h) // registered first, so it runs last: after the health and attestation steps
	defer b.fillLentBaseline(ctx, h, herr == nil)
	defer b.syncAdmission(ctx, h, herr == nil) // after the health state below is stored
	forced := false                            // the fail-closed check below made the hotel lent: save it once b.mu is free
	defer func() {
		if forced {
			b.saveLendStateLogged(h)
		}
	}()

	// A run this pass turned not billable is made durable after b.mu is
	// released, with a bound (usage_meter.go): no disk I/O under b.mu.
	usageMeterTurned := false
	defer func() {
		if usageMeterTurned {
			b.usageMeter.awaitDurable(usageTurnWait)
		}
	}()
	b.mu.Lock()
	defer b.mu.Unlock()
	// The usage meter sees the rooms this list showed, then ends the runs
	// the room map no longer holds. Deferred after the lock, so it runs
	// under b.mu once every change below is made (usage_meter.go).
	var listed []usageSighting
	defer func() { usageMeterTurned = b.usageMeterHotel(h, listed, listedAt, lerr == nil) }()
	now := time.Now()
	h.lastErr = ""
	if err := errors.Join(herr, qerr, lerr); err != nil {
		h.lastErr = err.Error()
	}
	h.listOK = lerr == nil
	hadHealth := !h.lastOK.IsZero()
	if herr == nil {
		h.lastOK, h.healthMs = now, healthMs
	}
	healthOK := !h.lastOK.IsZero() && now.Sub(h.lastOK) < okWindow
	// A slow health endpoint does not take a hotel out of placement while
	// the hotel still answers room calls (a sealed guest at full CPU answered
	// rooms but not health at about 1,000 rooms).
	callsOK := now.Sub(time.Unix(0, h.lastAnswer.Load())) < okWindow
	wasOK := h.ok
	h.ok = healthOK || (callsOK && !h.lastOK.IsZero())
	h.healthLate = !healthOK && h.ok
	cameUp := h.ok && !wasOK
	switch {
	case h.ok:
		if !h.downSince.IsZero() {
			log.Printf("hotel %s up again after %s down", h.cfg.ID, now.Sub(h.downSince).Round(time.Second))
		}
		h.downSince = time.Time{}
	case h.downSince.IsZero():
		h.downSince = now
		b.hotelWentDown(h)
		b.noteMinerDown(h, now)
		// A hotel that comes back must pass attestation again: it may have
		// rebooted into another binding.
		h.adm.attestedAt, h.adm.checkedAt = time.Time{}, time.Time{}
		if wasOK {
			log.Printf("hotel %s down: %s", h.cfg.ID, h.lastErr)
		}
	}
	b.alertHealth(h, herr, hadHealth)
	if cameUp {
		b.noteMinerUp(h, now)
	}
	if cameUp && b.prewarms(h) {
		go b.prewarmHotel(h)
	}
	if cameUp {
		go b.replayGuestPrefetch(h)
	}
	offered := h.slots // health late: the slots placement still uses
	slotsTrusted := herr == nil
	if slotsTrusted {
		slots := hd.Slots
		if h.cfg.MaxSlots > 0 && slots > h.cfg.MaxSlots {
			slots = h.cfg.MaxSlots
		}
		offered = max(slots, 0) // this tick's answer, even 0, which resize ignores
		h.resize(slots)
		if hd.Live.CPU != nil {
			h.cpuPct = *hd.Live.CPU
		}
		h.memPct, h.memGiB, h.load1 = hd.Live.MemPct, hd.Live.MemGiB, hd.Live.Load1
		h.roomDataPct = hd.Live.RoomDataPct
		if hd.SandboxesRunning != nil {
			h.containers = *hd.SandboxesRunning
		}
		// Only a good health answer moves the runtime: a failed fetch keeps
		// the last known value, and a good answer without one clears it (the
		// hotel may have rebooted into a kit that does not report it).
		h.healthRuntime.Store(hd.Runtime)
		h.kernelIsolation = hd.KernelIsolation
	}
	if qerr == nil {
		h.apiRunning = int(quota.Usage["running_sandboxes"] + quota.Usage["frozen_sandboxes"])
		h.apiDeleting = int(quota.Usage["deleting_sandboxes"])
		h.removingDiskGiB = int(quota.Usage["removing_disk_gib"])
	}
	// Slot delivery credits only a trusted health report this tick (AB#331).
	b.recordDelivery(h, offered, now, slotsTrusted) // before the room list return: a failed list does not stop the count
	if lerr != nil {
		return
	}
	seen := make(map[string]bool, len(list.Sandboxes))
	leftover := map[string]bool{} // recorded unreaped requests that still list a room
	// A new API start time means the hotel API restarted and forgot its
	// rooms: those this list misses went with it (AB#864).
	apiRestarted := list.APIStartedAt != "" && h.apiStartedAt != "" && list.APIStartedAt != h.apiStartedAt
	if list.APIStartedAt != "" {
		h.apiStartedAt = list.APIStartedAt
	}
	for _, s := range list.Sandboxes {
		seen[s.ID] = true
		// A room a failed create left behind is not the guest's room: the
		// guest got its room elsewhere or an error. It is never adopted (or
		// billed) under the guest label; it waits for its removal.
		if ub := h.unreaped[s.Labels[batchLabel]]; ub != nil && ub.guest == s.Labels[guestLabel] && !ub.keep[s.ID] {
			leftover[s.Labels[batchLabel]] = true
			if rm := h.rooms[s.ID]; rm != nil { // adopted before the request was recorded
				b.release(h, rm)
			}
			continue
		}
		if rm := h.rooms[s.ID]; rm != nil {
			if d := diskGiBOf(s.Resources); d > 0 {
				rm.diskGiB = d
			}
			rm.noteListed(s.Labels, s.ExpiresAt, s.EndReason)
			if rm.state == stDeleting && !rm.deleteSent {
				// A list that missed the room (built before its create landed)
				// marked it deleting; the hotel lists it, so it runs.
				rm.state, rm.since, rm.vanished, rm.hotelRestarted = stRunning, now, time.Time{}, false
				if rm.slot < 0 {
					h.place(rm)
				}
			}
			continue
		}
		rm := &room{hid: s.ID, id: h.cfg.ID + "." + s.ID, h: h, guest: s.Labels[guestLabel], state: stRunning, since: now, born: now, diskGiB: diskGiBOf(s.Resources)}
		rm.noteListed(s.Labels, s.ExpiresAt, s.EndReason)
		h.rooms[s.ID] = rm
		b.register(rm)
		h.place(rm)
		b.forgetEnded(rm.guest, rm.id) // a late list: the room is back
	}
	for _, s := range list.Sandboxes {
		// Every listed room uses compute. One not in the room map is a
		// recorded leftover of a failed create (usage_meter.go).
		if rm := h.rooms[s.ID]; rm != nil {
			listed = append(listed, usageSightingOf(h, rm, s.Resources))
		} else {
			listed = append(listed, usageListSighting(h, s.ID, s.Labels, s.Resources))
		}
	}
	for batchID, ub := range h.unreaped {
		switch {
		case ub.busy:
		case !leftover[batchID] && b.holdsLocked(h, batchID, ub, listAsked): // a lost create may still start its room (allowance.go)
		case !leftover[batchID]:
			delete(h.unreaped, batchID) // the hotel lists none of its rooms
			log.Printf("orphan rooms on hotel %s (batch %s) no longer listed", h.cfg.ID, batchID)
		default:
			ub.busy = true
			go func() {
				ok := b.reapPass(h, ub.guest, batchID, ub.keep, 10*time.Second)
				runAfterCleanupPass(h, batchID) // allowance.go
				if ok {
					b.reaped(h, batchID, ub) // ends the pass and decides the record in one step
					return
				}
				b.mu.Lock()
				ub.busy = false
				b.mu.Unlock()
			}()
		}
	}
	b.checkMinerExitRooms(h, seen)
	var hotelEnded map[string]string
	for _, e := range list.Ended {
		if hotelEndReasons[e.EndReason] {
			if hotelEnded == nil {
				hotelEnded = map[string]string{}
			}
			hotelEnded[e.ID] = e.EndReason
		}
	}
	var deleting []*room
	for hid, rm := range h.rooms {
		if !seen[hid] && rm.state == stRunning && now.Sub(rm.since) > 5*time.Second {
			rm.state, rm.vanished = stDeleting, now
			rm.hotelRestarted = apiRestarted
		}
		if why := hotelEnded[hid]; why != "" {
			rm.hotelEnd = why
		}
		if rm.state == stDeleting {
			deleting = append(deleting, rm)
		}
	}
	// The hotel keeps a gone room in a hidden "deleting" state until its
	// container is removed. Show that many of the most recently gone rooms
	// as deleting; free the rest.
	sort.Slice(deleting, func(i, j int) bool { return deleting[i].vanished.After(deleting[j].vanished) })
	for i, rm := range deleting {
		if seen[rm.hid] {
			continue // DELETE sent, record still listed
		}
		if i >= h.apiDeleting && now.Sub(rm.vanished) > 2*time.Second {
			b.endOfVanished(h, rm, now)
			b.release(h, rm)
		}
	}
	for i, rm := range h.grid {
		if rm != nil && rm.state == stFailed && now.Sub(rm.since) > 30*time.Second {
			h.grid[i] = nil
		}
	}
	forced = b.checkReservedRooms(h)
	h.roomsUnchecked = false
	b.listedLocked(h) // the metered recount of a joined hotel (allowance.go)
}

func (b *broker) syncLoop(ctx context.Context, h *hotel) {
	defer close(h.syncDone)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		b.syncHotel(ctx, h)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---------------------------------------------------------------- live view

// viewAuth is how a live view request got in.
type viewAuth struct {
	freshView  string     // ?token= view token to move into the bv_ cookie
	freshShare string     // ?share= token to move into the bvs_ cookie
	shareHash  string     // set when a share link let the request in; the stream rechecks it
	share      *liveShare // that link
	triedShare bool       // a share link or cookie was offered and did not work
}

// viewGuest checks the view token (?token= or the bv_<guest> cookie) and then
// a share link (?share= or the bvs_<guest> cookie, AB#584). A share link works
// for a guest with no view token.
func (b *broker) viewGuest(r *http.Request, guestID string) (*guestState, viewAuth) {
	var a viewAuth
	g := b.guests[guestID]
	if g == nil {
		return nil, a
	}
	if g.cfg.ViewTokenSHA256 != "" {
		want := []byte(strings.ToLower(g.cfg.ViewTokenSHA256))
		if t := r.URL.Query().Get("token"); t != "" && subtle.ConstantTimeCompare([]byte(sha(t)), want) == 1 {
			a.freshView = t
			return g, a
		}
		if c, err := r.Cookie("bv_" + guestID); err == nil && subtle.ConstantTimeCompare([]byte(sha(c.Value)), want) == 1 {
			return g, a
		}
	}
	if !g.cfg.LiveShares {
		return nil, a
	}
	if t := r.URL.Query().Get("share"); t != "" {
		a.triedShare = true
		if s := b.shareFor(sha(t), guestID); s != nil {
			a.freshShare, a.shareHash, a.share = t, sha(t), s
			return g, a
		}
	}
	if c, err := r.Cookie(liveShareCookiePfx + guestID); err == nil && c.Value != "" {
		a.triedShare = true
		if s := b.shareFor(sha(c.Value), guestID); s != nil {
			a.shareHash, a.share = sha(c.Value), s
			return g, a
		}
	}
	return nil, a
}

// writeSignIn answers 401 with a form that asks for the view token. The form posts the token in the body,
// so it does not stay in the browser history like a ?token= link.
func writeSignIn(w http.ResponseWriter, guestID, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(401)
	note := "Enter the view token, or open the link that has the token."
	if msg != "" {
		note = msg
	}
	_, _ = fmt.Fprintf(w, `<!doctype html><meta name="viewport" content="width=device-width"><title>Central booking</title>
<body style="font:16px system-ui;background:#0A0A1A;color:#F0F0F5;padding:24px">
<form method="post" action="/%s/live/sign-in" style="display:flex;flex-direction:column;gap:12px;max-width:420px">
<label for="token">%s</label>
<input id="token" name="token" type="password" autocomplete="current-password" required style="font:16px system-ui;padding:8px">
<button type="submit" style="font:16px system-ui;padding:8px">Sign in</button>
</form></body>`, url.PathEscape(guestID), html.EscapeString(note))
}

// handleSignIn: POST /<guest>/live/sign-in with form field "token" sets the
// view cookie and redirects to the live view.
func (b *broker) handleSignIn(w http.ResponseWriter, r *http.Request, guestID string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	token := ""
	if r.ParseForm() == nil {
		token = r.PostForm.Get("token")
	}
	g := b.guests[guestID]
	if g == nil || g.cfg.ViewTokenSHA256 == "" || token == "" ||
		subtle.ConstantTimeCompare([]byte(sha(token)), []byte(strings.ToLower(g.cfg.ViewTokenSHA256))) != 1 {
		writeSignIn(w, guestID, "The token is not correct. Try again.")
		return
	}
	b.setViewCookie(w, guestID, token)
	http.Redirect(w, r, "/"+guestID+"/live", http.StatusSeeOther)
}

func (b *broker) setViewCookie(w http.ResponseWriter, guestID, token string) {
	// Lax, not Strict: a link opened from another app (for example a
	// terminal) is a cross-site navigation, and Strict would drop the
	// cookie on the redirect that follows.
	http.SetCookie(w, &http.Cookie{Name: "bv_" + guestID, Value: token, Path: "/" + guestID + "/", MaxAge: 30 * 86400,
		HttpOnly: true, Secure: !b.cfg.InsecureCookie, SameSite: http.SameSiteLaxMode})
}

func (b *broker) handleLive(w http.ResponseWriter, r *http.Request, guestID, tail string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	g, a := b.viewGuest(r, guestID)
	if g == nil {
		msg := ""
		if a.triedShare {
			msg = "This share link has ended or was revoked. Ask the person who sent it for a new one."
		}
		writeSignIn(w, guestID, msg)
		return
	}
	if a.freshView != "" {
		b.setViewCookie(w, guestID, a.freshView)
		http.Redirect(w, r, "/"+guestID+"/live", http.StatusSeeOther)
		return
	}
	if a.freshShare != "" {
		// Move the token out of the address bar and into a cookie that ends with the link.
		b.setShareCookie(w, guestID, a.freshShare, a.share.Expires)
		http.Redirect(w, r, "/"+guestID+"/live", http.StatusSeeOther)
		return
	}
	switch tail {
	case "live":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'")
		_, _ = w.Write(liveHTML)
	case "live/events":
		b.stream(w, r, g, a.shareHash)
	default:
		http.NotFound(w, r)
	}
}

func (b *broker) snapshot(g *guestState) map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	cut := 0
	for cut < len(g.recent) && now.Sub(g.recent[cut]) > 60*time.Second {
		cut++
	}
	g.recent = g.recent[cut:]
	perSec := 0
	for _, t := range g.recent {
		if now.Sub(t) <= 5*time.Second {
			perSec++
		}
	}
	tot := map[string]int{"running": 0, "creating": 0, "deleting": 0, "failed_now": 0}
	hotels := []any{}
	for _, h := range b.hotelList() {
		grid := make([]byte, len(h.grid))
		mine := map[byte]int{}
		seen := map[*room]bool{}
		for i, rm := range h.grid {
			switch {
			case rm == nil:
				grid[i] = stFree
			case rm.guest == g.cfg.ID:
				grid[i] = rm.state
				seen[rm] = true
				mine[rm.state]++
			default:
				grid[i] = stOther
			}
		}
		// A room can be in h.rooms with no square (slot -1 after a grid
		// shrink or a failed place). It still counts as the guest's, once
		// (AB#577).
		for _, rm := range h.rooms {
			if rm.guest == g.cfg.ID && !seen[rm] {
				seen[rm] = true
				mine[rm.state]++
			}
		}
		owned := mine[stRunning] + mine[stCreating] + mine[stDeleting] + mine[stFailed]
		// Same reach rule as the guest capacity view (allowed list,
		// reservation, lend, miner opt-in), except a hotel that still holds
		// the guest's rooms stays visible after the operator narrows the
		// guest's list (AB#577).
		if owned == 0 && g.tierOf(h) == "" {
			continue
		}
		tot["running"] += mine[stRunning]
		tot["creating"] += mine[stCreating]
		tot["deleting"] += mine[stDeleting]
		tot["failed_now"] += mine[stFailed]
		doc := map[string]any{
			"id": h.cfg.ID, "name": h.cfg.Name, "threads": h.cfg.Threads, "ram_gib": h.cfg.RAMGiB, "slots": h.slots, "ok": h.ok, "drain": h.drain(), "sealed": h.cfg.Sealed,
			"grid": string(grid), "cpu": h.cpuPct, "mem_pct": h.memPct, "mem_gib": h.memGiB, "load1": h.load1,
			"containers": h.containers,
			"queued":     h.queued, "creating": h.creating,
			"seen_age_s": seenAge(h.lastOK, now), "down_since": downSince(h), "health_late": h.healthLate, "health_ms": h.healthMs, "list_ok": h.listOK, "caps": h.caps,
			"mine": map[string]int{"running": mine[stRunning], "creating": mine[stCreating], "deleting": mine[stDeleting], "failed": mine[stFailed]},
		}
		// All-guest counts only where this guest owns a room (AB#577).
		if owned > 0 {
			doc["rooms_all"], doc["deleting_all"] = h.apiRunning, h.apiDeleting
		}
		hotels = append(hotels, doc)
	}
	return map[string]any{
		"t": now.UnixMilli(), "guest": g.cfg.ID, "hotels": hotels,
		"totals": map[string]any{"running": tot["running"], "creating": tot["creating"], "deleting": tot["deleting"],
			"queued": g.queued, "created": g.created, "failed": g.failed, "rejected": g.rejected, "creates_per_s": float64(perSec) / 5},
	}
}

func seenAge(t, now time.Time) float64 {
	if t.IsZero() {
		return -1
	}
	return float64(now.Sub(t).Milliseconds()) / 1000
}

// stream sends a snapshot each second. shareHash is set when a share link let
// the request in: the stream ends once that link is revoked or expires.
func (b *broker) stream(w http.ResponseWriter, r *http.Request, g *guestState, shareHash string) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no streaming", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	t := time.NewTicker(time.Second)
	defer t.Stop()
	endSeq := b.endedStreamStart(g.cfg.ID, time.Now())
	for {
		if shareHash != "" && b.shareFor(shareHash, g.cfg.ID) == nil {
			return
		}
		data, _ := json.Marshal(b.snapshot(g))
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return
		}
		// One room_gone per end record since the last tick (AB#864).
		var gone []map[string]any
		gone, endSeq = b.endedSince(g.cfg.ID, endSeq)
		for _, ev := range gone {
			raw, _ := json.Marshal(ev)
			if _, err := fmt.Fprintf(w, "event: room_gone\ndata: %s\n\n", raw); err != nil {
				return
			}
		}
		fl.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
		}
	}
}

// ---------------------------------------------------------------- routing

func (b *broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/healthz" {
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	if (p == "/v1/broker/hotels" && r.Method != "GET") || strings.HasPrefix(p, "/v1/broker/hotels/") {
		b.handleHotelAdmin(w, r, strings.TrimPrefix(strings.TrimPrefix(p, "/v1/broker/hotels"), "/"))
		return
	}
	if p == "/v1/broker/capacity" && r.Method == "GET" && b.isOperator(r) {
		b.handleCapacity(w, nil, false) // every hotel; a guest key gets its own view (serveNative)
		return
	}
	if p == "/v1/broker/capacity" && r.Method == "GET" && b.isMinerEnroller(r) {
		b.handleCapacity(w, nil, true) // miner hotels only
		return
	}
	if p == "/v1/broker/capacity" && r.Method == "GET" && b.isOperatorReader(r) {
		b.handleCapacity(w, nil, false) // read-only key: operator view, no other route
		return
	}
	if strings.HasPrefix(p, "/v1/broker/bindings/") && r.Method == "GET" && b.isOperator(r) {
		id := strings.TrimPrefix(p, "/v1/broker/bindings/")
		if sha, ok := strings.CutSuffix(id, "/receipts"); ok {
			b.handleChainGet(w, sha) // operator key only
			return
		}
		b.handleBindingGet(w, id) // operator key only
		return
	}
	if p == "/v1/broker/acme-challenge" {
		b.handleACMEChallenge(w, r) // signed by the hotel's attested receipt key, no Bearer key
		return
	}
	if p == "/v1/broker/miner-exits" && r.Method == "GET" && (b.isOperator(r) || b.isOperatorReader(r)) {
		b.handleMinerExits(w, r) // miner hotels that went down with customer rooms
		return
	}
	if p == "/v1/broker/usage-meter" {
		b.handleUsageMeter(w, r) // operator key only
		return
	}
	if id, action, ok := meterRoute(p); ok {
		b.handleMeter(w, r, id, action) // meter key only (meter.go)
		return
	}
	if p == "/v1/broker/guests" || strings.HasPrefix(p, "/v1/broker/guests/") {
		b.handleGuestAdmin(w, r, strings.TrimPrefix(strings.TrimPrefix(p, "/v1/broker/guests"), "/"))
		return
	}
	if strings.HasPrefix(p, "/v1/") {
		g := b.guestFromKey(r)
		if g == nil {
			if isCompat(r) {
				compatErr(w, 401, "unauthorized", "missing or unknown Bearer key", 0)
				return
			}
			writeErr(w, 401, "unauthorized", "missing or unknown Bearer key")
			return
		}
		if isCompat(r) {
			b.serveCompat(w, r, g)
			return
		}
		b.serveNative(w, r, g)
		return
	}
	// /<guest>/live and /<guest>/live/events
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)
	if len(parts) == 2 && parts[1] == "live/sign-in" && r.Method == "POST" {
		b.handleSignIn(w, r, parts[0])
		return
	}
	if len(parts) == 2 && (parts[1] == "live" || parts[1] == "live/events") {
		b.handleLive(w, r, parts[0], parts[1])
		return
	}
	http.NotFound(w, r)
}

func (b *broker) serveNative(w http.ResponseWriter, r *http.Request, g *guestState) {
	p := r.URL.Path
	{
		switch {
		case p == "/v1/sandboxes" && r.Method == "POST":
			b.handleCreate(w, r, g)
		case p == "/v1/sandboxes/catalog" && r.Method == "GET":
			b.compatCatalog(w, g)
		case p == "/v1/sandboxes" && r.Method == "GET":
			b.handleList(w, r, g)
		case p == "/v1/sandboxes" && r.Method == "DELETE":
			b.handleBulkDelete(w, r, g)
		case p == "/v1/sandboxes/ended" && r.Method == "GET":
			// Before the room route. No room id collides: a broker id is
			// always <hotel>.<hotel room id>, with a dot.
			b.handleEnded(w, r, g)
		case strings.HasPrefix(p, "/v1/sandboxes/"):
			b.handleRoom(w, r, g, strings.TrimPrefix(p, "/v1/sandboxes/"))
		case strings.HasPrefix(p, "/v1/hotels/"):
			b.handleHotelDoc(w, r, strings.TrimPrefix(p, "/v1/hotels/"), g)
		case p == "/v1/quota" && r.Method == "GET":
			b.handleQuota(w, r, g)
		case p == "/v1/usage" && r.Method == "GET":
			b.handleUsage(w, r, g)
		case p == "/v1/images" && r.Method == "GET":
			b.handleImageList(w, r, g) // guest_images.go
		case p == "/v1/images/pins" && r.Method == "DELETE":
			b.handleUnpin(w, r, g)
		case p == "/v1/images/prefetch" && r.Method == "POST":
			b.handlePrefetch(w, r, g)
		case strings.HasPrefix(p, "/v1/images/prefetch/") && r.Method == "GET":
			b.handlePrefetchStatus(w, g, strings.TrimPrefix(p, "/v1/images/prefetch/"))
		case p == "/v1/snapshots" && r.Method == "GET":
			b.handleSnapshotList(w, r, g)
		case strings.HasPrefix(p, "/v1/snapshots/"):
			b.handleSnapshot(w, r, g, strings.TrimPrefix(p, "/v1/snapshots/"))
		case p == "/v1/workspaces" && (r.Method == "GET" || r.Method == "POST"):
			b.handleWorkspaces(w, r, g)
		case strings.HasPrefix(p, "/v1/workspaces/"):
			b.handleWorkspace(w, r, g, strings.TrimPrefix(p, "/v1/workspaces/"))
		case p == "/v1/secrets" || strings.HasPrefix(p, "/v1/secrets/"):
			name, ok := secretRoute(p)
			if !ok {
				writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+p)
				return
			}
			b.handleSecrets(w, r, g, name)
		case p == "/v1/live/shares" || strings.HasPrefix(p, "/v1/live/shares/"):
			b.handleLiveShares(w, r, g, strings.TrimPrefix(strings.TrimPrefix(p, "/v1/live/shares"), "/"))
		case p == "/v1/broker/hotels" && r.Method == "GET":
			b.handleHotels(w, g)
		case p == "/v1/broker/capacity" && r.Method == "GET":
			b.handleCapacity(w, g, false)
		case p == "/v1/broker/stats":
			b.handleStats(w, r, g)
		case p == "/v1/broker/probe" && r.Method == "POST":
			if !g.cfg.Ops {
				writeErr(w, 403, "forbidden", "this key may not run the probe")
				return
			}
			b.handleProbe(w, r, g)
		case p == "/v1/status":
			// A guest counts its own hotels (AB#869); an ops key the fleet.
			b.mu.Lock()
			n, up := 0, 0
			for _, h := range b.hotelList() {
				if !g.cfg.Ops && !g.guestReaches(h) {
					continue
				}
				n++
				if h.ok {
					up++
				}
			}
			b.mu.Unlock()
			writeJSON(w, 200, map[string]any{"service": "central-booking", "hotels": n, "hotels_up": up, "uptime_s": int(time.Since(b.started).Seconds())})
		default:
			writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+p)
		}
	}
}

// count 429s sent to guests (no free rooms) for the live counters.
type countingWriter struct {
	http.ResponseWriter
	status int
}

func (c *countingWriter) WriteHeader(s int) { c.status = s; c.ResponseWriter.WriteHeader(s) }
func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the server's writer, so the
// terminal WebSocket can hijack the connection (terminal_ws.go).
func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// handler is the broker as served: ServeHTTP plus the 429 counter.
func (b *broker) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw := &countingWriter{ResponseWriter: w, status: 200}
		b.ServeHTTP(cw, r)
		if cw.status == 429 && r.URL.Path == "/v1/sandboxes" && r.Method == "POST" {
			if g := b.guestFromKey(r); g != nil {
				b.mu.Lock()
				g.rejected++
				b.mu.Unlock()
			}
		}
	})
}

func main() {
	cfgPath := flag.String("config", "/etc/thin-broker/config.json", "private config file")
	printDigest := flag.Bool("print-catalog-digest", false, "print the compiled-in catalog digest and exit; reads no config (AB#546 swap check)")
	flag.Parse()
	if *printDigest {
		if err := printCatalogDigest(os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	b, err := loadBroker(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if strings.TrimSpace(b.cfg.Listen) == "" {
		log.Fatal("config: listen is required (an empty listen would bind :http on every interface)")
	}
	ctx, stopLoops := context.WithCancel(context.Background())
	if err := b.loadCompat(); err != nil {
		log.Printf("client state not loaded: %v", err)
	}
	b.loadNativeExecs()
	if err := b.loadRuntimeHotels(); err != nil {
		log.Printf("runtime hotels not loaded: %v", err)
	}
	b.loadCaps()          // after the runtime hotels, or their probe results are dropped
	b.resumeNativeExecs() // after every hotel is known: re-attach execs that ran across the restart (AB#756)
	saved := make(chan struct{})
	go func() {
		b.saveLoop(ctx)
		close(saved)
	}()
	go b.alerts.run(ctx)
	go b.usageMeter.run(ctx)
	for _, h := range b.hotelList() {
		b.startSync(ctx, h)
	}
	handler := b.handler()
	// No WriteTimeout: an exec may run for hours. IdleTimeout closes kept-alive
	// connections that send nothing, so they cannot pile up to the fd limit.
	srv := &http.Server{Addr: b.cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	// A restart (systemctl sends SIGTERM) stops taking requests, lets the ones
	// in flight finish for a short while, then writes the client state: ids
	// and idempotency answers from the last second must not be lost.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-stop
		log.Printf("%s: stopping, saving client state", sig)
		b.stopNativeResume() // re-attach loops end now; the next broker picks them up
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		b.drainNativeExecs(nativeExecDrain) // background execs get time to finish and be saved
		stopLoops()
		<-saved // saveLoop writes dirty state on its way out
		b.usageMeter.checkpoint(time.Now())
		if err := b.usageMeter.flush(); err != nil {
			log.Printf("usage meter: readings not written at stop: %v", err)
		}
		os.Exit(0)
	}()
	log.Printf("central booking on %s: %d hotels, %d guests", b.cfg.Listen, len(b.hotelList()), len(b.guests))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	select {} // the signal goroutine exits the process
}

// errCodeOf reads error.code from a hotel's JSON error body.
func errCodeOf(body []byte) string {
	var doc struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &doc)
	return doc.Error.Code
}

// guestImageFault reports whether a hotel's image_pull_failed message names
// a missing or denied image (the guest's error) rather than a hotel fault.
// registryRateLimited reports a pull the registry refused for its rate limit.
func registryRateLimited(body []byte) bool {
	var doc struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &doc)
	return strings.Contains(strings.ToLower(doc.Error.Message), "toomanyrequests")
}

func guestImageFault(body []byte) bool {
	var doc struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &doc)
	m := strings.ToLower(doc.Error.Message)
	for _, s := range []string{"manifest unknown", "not found", "pull access denied", "repository does not exist", "invalid reference format", "unauthorized"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}
