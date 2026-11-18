package snpverify

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
)

// The checks in this file mirror what verify_receipts.py main() runs after
// verify_receipts() on every sealed run with default options: guest TLS (default
// mode), policy_timeline, room_tunables and room_links. Where Python would crash
// on a missing field or a wrong type, this fails.

// AllResult is what VerifyAll reports on success.
type AllResult struct {
	Attestation    Result                   `json:"attestation"`
	Chain          ReceiptsResult           `json:"chain"`
	PolicyTimeline map[string][]PolicyEvent `json:"policy_timeline"`
	RoomTunables   map[string]string        `json:"room_tunables"`
	RoomLinks      map[string]string        `json:"room_links"`
	// Checked names the optional checks that found something to check in this list.
	Checked []string `json:"-"`
}

// PolicyEvent is one signed policy event of a room, in chain order.
type PolicyEvent struct {
	Sequence     int64  `json:"sequence"`
	IssuedAt     any    `json:"issued_at"`
	Action       string `json:"action"`
	Status       any    `json:"status"`
	Mode         any    `json:"mode,omitempty"`
	Allow        any    `json:"allow,omitempty"`
	PolicySHA256 string `json:"policy_sha256,omitempty"`
}

// VerifyAll runs everything the Python checker runs by default, in its order:
// attestation, guest TLS fields, receipts, network policy, tunables, sandbox
// links. Call this, not the parts, so no check is forgotten.
func VerifyAll(att Attestation, receipts []Receipt, head string, opts Options) (AllResult, error) {
	return VerifyAllWithList(att, receipts, head, opts, nil)
}

// VerifyAllWithList is VerifyAll for a receipts document that is an object: list is
// its count and room_head, which the per-room checks compare with the receipts.
func VerifyAllWithList(att Attestation, receipts []Receipt, head string, opts Options, list *ListDoc) (AllResult, error) {
	var out AllResult
	var err error
	if out.Attestation, err = VerifyAttestation(att, opts); err != nil {
		return out, err
	}
	if err = verifyGuestTLS(att); err != nil {
		return out, err
	}
	if err = verifyGuestIngress(att); err != nil {
		return out, err
	}
	if out.Chain, err = VerifyReceipts(att, receipts, head); err != nil {
		return out, err
	}
	if err = checkSnapshotEdges(receipts); err != nil {
		return out, err
	}
	numbered, err := checkRoomNumbering(receipts, list)
	if err != nil {
		return out, err
	}
	poolLinks, pools, err := checkPoolRooms(receipts)
	if err != nil {
		return out, err
	}
	if out.PolicyTimeline, err = policyTimeline(receipts); err != nil {
		return out, err
	}
	if out.RoomTunables, err = roomTunables(receipts); err != nil {
		return out, err
	}
	if out.RoomLinks, err = roomLinks(receipts); err != nil {
		return out, err
	}
	for room, link := range poolLinks { // a pre-made room is linked by its claim
		out.RoomLinks[room] = link
	}
	if numbered > 0 {
		out.Checked = append(out.Checked, "each numbered room: its receipts run 1 to n with no gap and every link right")
	}
	if pools > 0 {
		out.Checked = append(out.Checked, "pool rooms: each claim is receipt 2 of its room and names the create it was made from")
	}
	return out, nil
}

func sha256Canonical(v any) (string, error) {
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	return sha256Hex(c), nil
}

func sortedBySequence(receipts []Receipt) []Receipt {
	out := append([]Receipt(nil), receipts...)
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := sequenceOf(out[i].Statement)
		b, _ := sequenceOf(out[j].Statement)
		return a < b
	})
	return out
}

// roomOf returns the receipt's room id; an absent, null or empty id means no room.
func roomOf(st map[string]any) string {
	room, _ := st["sandbox_id"].(string)
	return room
}

func policyTimeline(receipts []Receipt) (map[string][]PolicyEvent, error) {
	out := map[string][]PolicyEvent{}
	for _, rc := range sortedBySequence(receipts) {
		st := rc.Statement
		room := roomOf(st)
		if room == "" {
			continue
		}
		seq, _ := sequenceOf(st)
		action, _ := st["action"].(string)
		issued := st["issued_at"]
		status := st["status"]
		policy := st["network_policy"]
		_, known := out[room]
		if policy == nil && !(known && action == "delete") {
			continue
		}
		// Python needs both to be integers (not null) before it reads either event.
		if !isInt64(issued) {
			return nil, fail(CodeNetworkPolicyMismatch, "receipt %d: issued_at is not an integer", seq)
		}
		if !isInt64(status) {
			return nil, fail(CodeNetworkPolicyMismatch, "receipt %d: status is not an integer", seq)
		}
		if policy == nil {
			out[room] = append(out[room], PolicyEvent{Sequence: seq, IssuedAt: issued, Action: "delete", Status: status})
			continue
		}
		obj := policy.(map[string]any) // an object, by the receipt type rules
		mode, hasMode := obj["mode"]
		allow, hasAllow := obj["allow"]
		if !hasMode {
			return nil, fail(CodeNetworkPolicyMismatch, "receipt %d: network_policy has no mode", seq)
		}
		if !hasAllow {
			return nil, fail(CodeNetworkPolicyMismatch, "receipt %d: network_policy has no allow", seq)
		}
		if _, ok := mode.(string); !ok {
			return nil, fail(CodeNetworkPolicyMismatch, "receipt %d: network_policy mode is not a string", seq)
		}
		if _, ok := allow.([]any); !ok {
			return nil, fail(CodeNetworkPolicyMismatch, "receipt %d: network_policy allow is not a list", seq)
		}
		sum, err := sha256Canonical(policy)
		if err != nil {
			return nil, fail(CodeNetworkPolicyMismatch, "receipt %d: network_policy: %v", seq, err)
		}
		if stored, _ := st["network_policy_sha256"].(string); stored != sum {
			return nil, fail(CodeNetworkPolicyMismatch, "receipt %d: network_policy_sha256 does not match the policy", seq)
		}
		out[room] = append(out[room], PolicyEvent{Sequence: seq, IssuedAt: issued, Action: action, Status: status,
			Mode: mode, Allow: allow, PolicySHA256: sum})
	}
	return out, nil
}

func roomTunables(receipts []Receipt) (map[string]string, error) {
	out := map[string]string{}
	for _, rc := range receipts {
		st := rc.Statement
		if action, _ := st["action"].(string); action != "create" {
			continue
		}
		tunables, present := st["tunables"]
		if !present {
			continue
		}
		seq, _ := sequenceOf(st)
		sum, err := sha256Canonical(tunables)
		if err != nil {
			return nil, fail(CodeTunablesMismatch, "receipt %d: tunables: %v", seq, err)
		}
		if stored, _ := st["tunables_sha256"].(string); stored != sum {
			return nil, fail(CodeTunablesMismatch, "receipt %d: tunables_sha256 does not match the tunables", seq)
		}
		if room := roomOf(st); room != "" {
			out[room] = sum
		}
	}
	return out, nil
}

// isLowerUUID is the SANDBOX_LINK_RE fullmatch: 8-4-4-4-12 lower-case hex, nothing else.
func isLowerUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func roomLinks(receipts []Receipt) (map[string]string, error) {
	out := map[string]string{}
	for _, rc := range receipts {
		st := rc.Statement
		if action, _ := st["action"].(string); action != "create" {
			continue
		}
		rawLink, present := st["cathedral_sandbox_id"]
		if !present {
			continue
		}
		seq, _ := sequenceOf(st)
		link, isStr := rawLink.(string)
		if !isStr || !isLowerUUID(link) {
			return nil, fail(CodeSandboxLinkMalformed, "receipt %d: cathedral_sandbox_id is not a lower-case UUID", seq)
		}
		room := roomOf(st)
		if room == "" {
			continue
		}
		// status is an integer or null by the receipt type rules; null reads as 0.
		status := int64(0)
		if n, ok := st["status"].(json.Number); ok {
			status, _ = n.Int64()
		}
		if status < 200 || status >= 300 {
			continue
		}
		out[room] = link
	}
	return out, nil
}

// b64Key32 mirrors _b64_key: base64 with validate=True, exactly 32 bytes.
// Python rejects newlines here, but Go's decoder would skip them, so refuse them first.
func b64Key32(v any) bool {
	s, ok := v.(string)
	if !ok || strings.ContainsAny(s, "\r\n") {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	return err == nil && len(raw) == 32
}

func isHex64Lower(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// verifyGuestIngress is verify_guest_ingress(att) with its defaults: a binding with no
// guest_ingress passes; one that names it must be a cathedral_guest_ingress_v1 object
// with a 64 lower-case hex TLS key (AB#422).
func verifyGuestIngress(att Attestation) error {
	ingress := att.Binding["guest_ingress"]
	if ingress == nil {
		return nil
	}
	obj, ok := ingress.(map[string]any)
	if !ok || obj["schema"] != "cathedral_guest_ingress_v1" {
		return fail(CodeGuestTLSMalformed, "binding guest_ingress is not a cathedral_guest_ingress_v1 object")
	}
	if tls, ok := obj["tls_spki_sha256"].(string); !ok || !isHex64Lower(tls) {
		return fail(CodeGuestTLSMalformed, "binding guest_ingress.tls_spki_sha256 is not 64 lower-case hex")
	}
	return nil
}

// verifyGuestTLS is verify_guest_tls(att) with its defaults (no peer SPKI, not
// required): a binding with no TLS key passes; one that names a key must be well formed.
func verifyGuestTLS(att Attestation) error {
	b := att.Binding
	tls := b["tls_spki_sha256"]
	if tls == nil {
		return nil
	}
	if s, ok := tls.(string); !ok || !isHex64Lower(s) {
		return fail(CodeGuestTLSMalformed, "binding tls_spki_sha256 is not 64 lower-case hex")
	}
	if !b64Key32(b["hotel_key_install_x25519_b64"]) {
		return fail(CodeGuestTLSMalformed, "binding hotel_key_install_x25519_b64 is not a base64 32-byte key")
	}
	signers, ok := b["hotel_key_install_signers_ed25519_b64"].([]any)
	if !ok || len(signers) == 0 {
		return fail(CodeGuestTLSMalformed, "binding names no hotel key install signer")
	}
	for _, s := range signers {
		if !b64Key32(s) {
			return fail(CodeGuestTLSMalformed, "binding install signer is not a base64 32-byte key")
		}
	}
	if src, _ := b["hotel_key_source"].(string); src != "install" {
		return fail(CodeGuestTLSMalformed, "binding hotel_key_source is not install")
	}
	return nil
}
