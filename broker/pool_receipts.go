// Ready rooms, proof (AB#894, phase 2 PR 2, design 6.5): a pool room is ready
// only when its receipt 1 is verified under the hotel's attested receipt key
// and binding.
//
// The receipts front (room-kit/room_receipts.py) signs every create and
// sends the receipt as X-Room-Receipt: base64url of canonical JSON
// {"statement", "signature_b64", "receipt_sha256"}. The signature is Ed25519
// over the canonical statement, and receipt_sha256 is its SHA-256. The
// statement is embedded in canonical form, so the bytes of the statement as
// they stand in the receipt are the signed bytes: nothing is re-encoded here.
//
// A pool room's receipt 1 is the front's signed create with "pool": true,
// which the front adds only to a pool create (label cathedral_pool "1", no
// Idempotency-Key, the five pool keys) whose room id nothing touched before
// the create was signed, made with the deny_all network. room_sequence 1
// and no room_previous_receipt_sha256 make it the room's first receipt.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	sealedReceiptSchema = "cathedral_sealed_hotel_receipt_v1"
	hotelReceiptSchema  = "cathedral_hotel_receipt_v1" // level 1: the rig only
	hotelBindingSchema  = "cathedral_hotel_binding_v1"
)

// poolAttest is what a pool room is proven under: the hotel's attested
// binding and its receipt key, and the receipt schema that binding signs.
type poolAttest struct {
	binding string // binding_sha256, lower case
	key     ed25519.PublicKey
	schema  string
}

func (a poolAttest) same(o poolAttest) bool {
	return a.binding == o.binding && bytes.Equal(a.key, o.key)
}

// errPoolReceiptBinding is a receipt that names another binding than the
// attested one: the front restarted (a new chain), or the attestation is
// old. It cannot be verified with the key in hand.
var errPoolReceiptBinding = errors.New("the receipt names another binding than the hotel's attested one")

type signedReceipt struct {
	Statement     json.RawMessage `json:"statement"`
	SignatureB64  string          `json:"signature_b64"`
	ReceiptSHA256 string          `json:"receipt_sha256"`
}

type poolStatement struct {
	Schema        string  `json:"schema"`
	BindingSHA256 string  `json:"binding_sha256"`
	Action        string  `json:"action"`
	SandboxID     *string `json:"sandbox_id"`
	Status        *int    `json:"status"`
	Pool          *bool   `json:"pool"`
	Image         *string `json:"image"`
	NetworkPolicy *struct {
		Mode        string          `json:"mode"`
		Allow       []string        `json:"allow"`
		Credentials json.RawMessage `json:"credentials"`
	} `json:"network_policy"`
	RoomSequence *int            `json:"room_sequence"`
	RoomPrevious json.RawMessage `json:"room_previous_receipt_sha256"`
}

// decodeReceiptHeader decodes an X-Room-Receipt value.
func decodeReceiptHeader(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, errors.New("no X-Room-Receipt")
	}
	if raw, err := base64.URLEncoding.DecodeString(v); err == nil {
		return raw, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, errors.New("X-Room-Receipt is not base64url")
	}
	return raw, nil
}

// verifyPoolReceipt1 checks that raw is room hid's receipt 1, a pool create,
// signed under att. It returns the receipt's sha256 and the image it names.
func verifyPoolReceipt1(raw []byte, att poolAttest, hid string) (receiptSHA, image string, err error) {
	var rc signedReceipt
	if json.Unmarshal(raw, &rc) != nil || len(rc.Statement) == 0 || rc.Statement[0] != '{' {
		return "", "", errors.New("not a signed receipt")
	}
	var st poolStatement
	if json.Unmarshal(rc.Statement, &st) != nil {
		return "", "", errors.New("statement is not a JSON object")
	}
	if !strings.EqualFold(st.BindingSHA256, att.binding) {
		return "", "", errPoolReceiptBinding
	}
	if len(att.key) != ed25519.PublicKeySize {
		return "", "", errors.New("no attested receipt key")
	}
	sum := sha256.Sum256(rc.Statement)
	if !strings.EqualFold(rc.ReceiptSHA256, hex.EncodeToString(sum[:])) {
		return "", "", errors.New("receipt_sha256 is not the statement's hash")
	}
	sig, err := base64.StdEncoding.DecodeString(rc.SignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(att.key, rc.Statement, sig) {
		return "", "", errors.New("signature does not verify under the attested receipt key")
	}
	switch {
	case st.Schema != att.schema:
		return "", "", fmt.Errorf("schema %q, want %q", st.Schema, att.schema)
	case st.Action != "create":
		return "", "", fmt.Errorf("action %q, not create", st.Action)
	case st.Status == nil || *st.Status < 200 || *st.Status > 299:
		return "", "", errors.New("not a successful create")
	case st.SandboxID == nil || *st.SandboxID != hid:
		return "", "", errors.New("the receipt names another room")
	case st.Pool == nil || !*st.Pool:
		return "", "", errors.New("the create is not signed pool: true")
	case st.NetworkPolicy == nil || st.NetworkPolicy.Mode != "deny_all" || len(st.NetworkPolicy.Allow) != 0 || len(st.NetworkPolicy.Credentials) != 0:
		return "", "", errors.New("the room network is not deny_all with an empty allow list")
	case st.RoomSequence == nil || *st.RoomSequence != 1 || !(len(st.RoomPrevious) == 0 || string(st.RoomPrevious) == "null"):
		return "", "", errors.New("not the room's first receipt")
	case st.Image == nil || *st.Image == "":
		return "", "", errors.New("the receipt names no image")
	}
	return strings.ToLower(rc.ReceiptSHA256), *st.Image, nil
}

// poolReceiptsPage is GET /v1/sandboxes/<room>/receipts as the front serves
// it: the room's receipts from the current front process's chain.
type poolReceiptsPage struct {
	SandboxID     string            `json:"sandbox_id"`
	BindingSHA256 string            `json:"binding_sha256"`
	Count         *int              `json:"count"`
	RoomHead      *string           `json:"room_head"`
	Receipts      []json.RawMessage `json:"receipts"`
}

// verifyPoolReceiptsPage reports whether page proves room hid unclaimed: it
// holds exactly one receipt, a verified pool receipt 1 under att (design 2.6
// step 7). Anything else is an error naming why.
func verifyPoolReceiptsPage(out []byte, att poolAttest, hid string) (receiptSHA, image string, err error) {
	var pg poolReceiptsPage
	if json.Unmarshal(out, &pg) != nil {
		return "", "", errors.New("the receipts list is not JSON")
	}
	if pg.SandboxID != hid {
		return "", "", errors.New("the receipts list names another room")
	}
	if !strings.EqualFold(pg.BindingSHA256, att.binding) {
		return "", "", errPoolReceiptBinding
	}
	if pg.Count == nil || *pg.Count != len(pg.Receipts) || len(pg.Receipts) != 1 {
		n := len(pg.Receipts)
		if pg.Count != nil {
			n = *pg.Count
		}
		return "", "", fmt.Errorf("%d receipts, not exactly one", n)
	}
	sha, image, err := verifyPoolReceipt1(pg.Receipts[0], att, hid)
	if err != nil {
		return "", "", err
	}
	if pg.RoomHead == nil || !strings.EqualFold(*pg.RoomHead, sha) {
		return "", "", errors.New("the room head is not its receipt 1")
	}
	return sha, image, nil
}
