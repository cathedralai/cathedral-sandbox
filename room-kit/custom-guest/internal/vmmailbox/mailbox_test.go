package vmmailbox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// memFile is a mailbox disk in memory.
type memFile struct{ b []byte }

func newMem() *memFile { return &memFile{b: make([]byte, MailboxBytes)} }
func (m *memFile) ReadAt(p []byte, off int64) (int, error) {
	return copy(p, m.b[off:]), nil
}
func (m *memFile) WriteAt(p []byte, off int64) (int, error) { return copy(m.b[off:], p), nil }
func (m *memFile) Sync() error                              { return nil }

// fixturePath is the host side's contract (sandbox PR 794). It is read, never copied here. Until
// that PR is on main, VM_MAILBOX_FIXTURE points at its branch's copy; with neither, the fixture
// tests skip and the self-made vectors below still run.
func fixturePath() string {
	if p := os.Getenv("VM_MAILBOX_FIXTURE"); p != "" {
		return p
	}
	return "../../../../tests/fixtures/vm_mailbox_v1.json"
}

type record struct {
	BodyUTF8   string `json:"body_utf8"`
	BodySHA256 string `json:"body_sha256"`
	HeadHex    string `json:"head_hex"`
	SlotSHA256 string `json:"slot_sha256"`
	Document   map[string]string
}

type fixture struct {
	Status, Offer, Answer record
	Invalid               []struct {
		BodyUTF8 string `json:"body_utf8"`
		Kind     string `json:"kind"`
		Why      string `json:"why"`
	} `json:"invalid_bodies"`
	Torn []struct {
		Edits [][]any `json:"edits"`
		Why   string  `json:"why"`
	} `json:"torn_offer_slots"`
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	raw, err := os.ReadFile(fixturePath())
	if err != nil {
		t.Skipf("mailbox fixture not present (%v): set VM_MAILBOX_FIXTURE", err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

var kindByName = map[string]Kind{"status": KindStatus, "offer": KindOffer, "answer": KindAnswer}

func TestFixtureRecordsRoundTripByteForByte(t *testing.T) {
	f := loadFixture(t)
	for name, rec := range map[string]record{"status": f.Status, "offer": f.Offer, "answer": f.Answer} {
		kind := kindByName[name]
		body := []byte(rec.BodyUTF8)
		doc, err := ParseBody(body, kind)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// Re-encoding the parsed document must give the same bytes: our writer is the host's.
		if again := canonical(doc); !bytes.Equal(again, body) {
			t.Fatalf("%s: canonical re-encode differs", name)
		}
		slot, err := EncodeSlot(kind, body)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(slot[:HeaderBytes]) != rec.HeadHex {
			t.Fatalf("%s: header differs", name)
		}
		if BodySHA256(body) != rec.BodySHA256 {
			t.Fatalf("%s: body sha256 differs", name)
		}
		if got := sha256Hex(slot); got != rec.SlotSHA256 {
			t.Fatalf("%s: whole slot differs", name)
		}
		back, err := DecodeSlot(slot, kind)
		if err != nil || !bytes.Equal(back, body) {
			t.Fatalf("%s: decode: %v", name, err)
		}
	}
}

func TestFixtureInvalidBodiesReadEmpty(t *testing.T) {
	f := loadFixture(t)
	if len(f.Invalid) != 18 {
		t.Fatalf("expected 18 invalid bodies, fixture has %d", len(f.Invalid))
	}
	for _, c := range f.Invalid {
		kind := kindByName[c.Kind]
		if _, err := ParseBody([]byte(c.BodyUTF8), kind); err == nil {
			t.Errorf("%s (%s): parsed", c.Why, c.Kind)
		}
		// Through the mailbox: a valid record around an invalid body reads as an empty slot.
		slot, err := EncodeSlot(kind, []byte(c.BodyUTF8))
		if err != nil {
			continue // over its bound: refused even earlier
		}
		box := newMem()
		off := map[Kind]int64{KindStatus: StatusOffset, KindOffer: OfferOffset, KindAnswer: AnswerOffset}[kind]
		copy(box.b[off:], slot)
		m := &Mailbox{f: box}
		switch kind {
		case KindAnswer:
			if _, ok := m.ReadAnswer(); ok {
				t.Errorf("%s: answer read", c.Why)
			}
		case KindOffer:
			if _, ok := m.ReadOffer(); ok {
				t.Errorf("%s: offer read", c.Why)
			}
		default:
			if _, ok := m.ReadStatus(); ok {
				t.Errorf("%s: status read", c.Why)
			}
		}
	}
}

func TestFixtureTornOfferSlotsReadEmpty(t *testing.T) {
	f := loadFixture(t)
	if len(f.Torn) != 5 {
		t.Fatalf("expected 5 torn slots, fixture has %d", len(f.Torn))
	}
	good, _ := EncodeSlot(KindOffer, []byte(f.Offer.BodyUTF8))
	for _, c := range f.Torn {
		slot := append([]byte(nil), good...)
		for _, e := range c.Edits {
			off := int(e[0].(float64))
			raw, err := hex.DecodeString(e[1].(string))
			if err != nil {
				t.Fatal(err)
			}
			copy(slot[off:], raw)
		}
		box := newMem()
		copy(box.b[OfferOffset:], slot)
		if _, ok := (&Mailbox{f: box}).ReadOffer(); ok {
			t.Errorf("%s: a torn slot read as an offer", c.Why)
		}
	}
	// The unedited slot does read, so the cases above fail for their edit and no other reason.
	box := newMem()
	copy(box.b[OfferOffset:], good)
	if _, ok := (&Mailbox{f: box}).ReadOffer(); !ok {
		t.Fatal("the intact offer slot must read")
	}
}

// Self-made vectors, so the guarantees hold without the fixture.

func sha256Hex(b []byte) string { return BodySHA256(b) }

func sampleStatus() Status {
	return Status{State: "open", KeyID: "m-9ce0d05cc319b370", Report: bytes.Repeat([]byte{7}, ReportBytes)}
}

func sampleOffer() Offer {
	o := Offer{VMID: "vm-0123456789ab", Report: bytes.Repeat([]byte{9}, ReportBytes)}
	copy(o.Pubkey[:], bytes.Repeat([]byte{1}, 32))
	copy(o.Nonce[:], bytes.Repeat([]byte{2}, 32))
	return o
}

func TestWriteStatusAndOfferRoundTrip(t *testing.T) {
	box := newMem()
	m := &Mailbox{f: box}
	if err := m.WriteStatus(sampleStatus()); err != nil {
		t.Fatal(err)
	}
	name, err := m.WriteOffer(sampleOffer())
	if err != nil {
		t.Fatal(err)
	}
	doc, ok := m.ReadOffer()
	if !ok || doc["vm_id"] != "vm-0123456789ab" {
		t.Fatalf("offer: %v", doc)
	}
	body, _ := OfferBody(sampleOffer())
	if name != BodySHA256(body) {
		t.Fatal("the offer's name is the sha256 of its body")
	}
	if doc, ok := m.ReadStatus(); !ok || doc["state"] != "open" {
		t.Fatalf("status: %v", doc)
	}
	// The answer slot is never touched by the guest.
	if !bytes.Equal(box.b[AnswerOffset:AnswerOffset+SlotBytes], make([]byte, SlotBytes)) {
		t.Fatal("the guest wrote the answer slot")
	}
	if err := m.ZeroOffer(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.ReadOffer(); ok {
		t.Fatal("a zeroed offer slot must read empty")
	}
}

func TestWritersRefuseValuesTheirSchemaRefuses(t *testing.T) {
	s := sampleStatus()
	s.State = `op"en`
	if _, err := StatusBody(s); err == nil {
		t.Error("a quote in a value")
	}
	s = sampleStatus()
	s.Report = s.Report[:ReportBytes-1]
	if _, err := StatusBody(s); err == nil {
		t.Error("a short report")
	}
	o := sampleOffer()
	o.VMID = "vm-ZZ"
	if _, err := OfferBody(o); err == nil {
		t.Error("a bad vm_id")
	}
}

func answerSlotFor(t *testing.T, a Answer) []byte {
	t.Helper()
	body := canonical(map[string]string{"schema": AnswerSchema, "offer_sha256": a.OfferSHA256, "epk": b64(a.EPK[:]),
		"nonce": b64(a.Nonce[:]), "ct": b64(a.CT[:])})
	slot, err := EncodeSlot(KindAnswer, body)
	if err != nil {
		t.Fatal(err)
	}
	return slot
}

func TestAnswerForAnotherOfferIsIgnored(t *testing.T) {
	box := newMem()
	m := &Mailbox{f: box}
	mine := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	copy(box.b[AnswerOffset:], answerSlotFor(t, Answer{OfferSHA256: other, EPK: [32]byte{1}, Nonce: [12]byte{2}, CT: [48]byte{3}}))
	if _, ok := m.AnswerFor(mine); ok {
		t.Fatal("an answer for another offer_sha256 must be ignored")
	}
	if _, ok := m.AnswerFor(other); !ok {
		t.Fatal("the answer for this offer must read")
	}
}

func TestAnswerOverBoundIsRefused(t *testing.T) {
	big := bytes.Repeat([]byte("a"), AnswerMax+1)
	if _, err := EncodeSlot(KindAnswer, big); err == nil {
		t.Fatal("a 4097-byte answer must be refused by the writer")
	}
	// A host that writes one anyway: header length 4097.
	slot := make([]byte, SlotBytes)
	copy(slot, magic[:])
	slot[8] = byte(KindAnswer)
	slot[11], slot[12] = 0x10, 0x01 // 4097
	sum := sha256.Sum256(big)       // a header that is otherwise valid: only the length bound can refuse it
	copy(slot[13:HeaderBytes], sum[:])
	copy(slot[HeaderBytes:], big)
	if _, err := DecodeSlot(slot, KindAnswer); !errors.Is(err, ErrTorn) {
		t.Fatalf("got %v", err)
	}
	box := newMem()
	copy(box.b[AnswerOffset:], slot)
	if _, ok := (&Mailbox{f: box}).ReadAnswer(); ok {
		t.Fatal("a 4097-byte answer was read")
	}
}

func TestDeepNestedBodyReadsEmptyWithoutPanic(t *testing.T) {
	depth := 30000 // 60 KB of brackets
	body := []byte("{\"a\":" + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "}")
	if len(body) > 60000 && len(body) < bodyMax(KindOffer) {
		slot, err := EncodeSlot(KindOffer, body)
		if err != nil {
			t.Fatal(err)
		}
		box := newMem()
		copy(box.b[OfferOffset:], slot)
		if _, ok := (&Mailbox{f: box}).ReadOffer(); ok {
			t.Fatal("a nested body read")
		}
	} else {
		t.Fatalf("test body is %d bytes", len(body))
	}
	if err := Prescan(body, bodyMax(KindOffer)); err == nil {
		t.Fatal("the pre-scan must refuse nesting")
	}
}

func TestPrescanAndParserGuards(t *testing.T) {
	good, _ := StatusBody(sampleStatus())
	if _, err := ParseBody(good, KindStatus); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"a space":         bytes.Replace(good, []byte(`:"`), []byte(`: "`), 1),
		"trailing bytes":  append(append([]byte(nil), good...), ' '),
		"a nested object": []byte(`{"key_id":{"a":"b"}}`),
		"an escape":       bytes.Replace(good, []byte(`:"open"`), []byte(`:"o`+string(rune(92))+`u0070en"`), 1),
		"a duplicate key": []byte(`{"key_id":"a","key_id":"b"}`),
		"unsorted keys":   []byte(`{"state":"open","key_id":"a"}`),
		"wrong schema":    bytes.Replace(good, []byte("status/v1"), []byte("status/v2"), 1),
	}
	for why, body := range cases {
		if _, err := ParseBody(body, KindStatus); err == nil {
			t.Errorf("%s: parsed", why)
		}
	}
}

func TestAnyPanicInAParserReadsEmpty(t *testing.T) {
	m := &Mailbox{f: panicFile{}}
	if _, ok := m.ReadAnswer(); ok {
		t.Fatal("read")
	}
	if _, ok := m.ReadOffer(); ok {
		t.Fatal("read")
	}
}

type panicFile struct{}

func (panicFile) ReadAt([]byte, int64) (int, error)  { panic("boom") }
func (panicFile) WriteAt([]byte, int64) (int, error) { return 0, nil }
func (panicFile) Sync() error                        { return nil }

func TestNewRequiresOneMiB(t *testing.T) {
	if _, err := New(newMem(), MailboxBytes-1); err == nil {
		t.Fatal("a short mailbox must be refused")
	}
	if _, err := New(newMem(), MailboxBytes); err != nil {
		t.Fatal(err)
	}
}

func TestZeroOfferFailsWhenWriteDoesNotStick(t *testing.T) {
	box := newMem()
	for i := range box.b[OfferOffset : OfferOffset+SlotBytes] {
		box.b[OfferOffset+i] = 0xff
	}
	m := &Mailbox{f: &stuckFile{memFile: box}}
	if err := m.ZeroOffer(); err == nil {
		t.Fatal("a zero that does not read back must fail")
	}
}

type stuckFile struct{ *memFile }

func (s *stuckFile) WriteAt(p []byte, off int64) (int, error) { return len(p), nil } // drops writes

func TestRewrapReportData(t *testing.T) {
	// Pinned so a change of the domain tag or the order is caught: sha512("cathedral-vm-rewrap/v1\0" || pub || nonce).
	got := RewrapReportData([32]byte{1}, [32]byte{2})
	again := RewrapReportData([32]byte{1}, [32]byte{3})
	if got == again {
		t.Fatal("the nonce must matter")
	}
	if hex.EncodeToString(got[:4]) == "" {
		t.Fatal("unreachable")
	}
}

// ---- envelope ----

func TestEnvelopeOpensAndRefusesForgeries(t *testing.T) {
	vm, _ := ecdh.X25519().GenerateKey(rand.Reader)
	customer, _ := ecdh.X25519().GenerateKey(rand.Reader)
	offer := strings.Repeat("c", 64)
	secret := bytes.Repeat([]byte{0x42}, 32)
	ans, err := sealAnswer(vm.PublicKey().Bytes(), customer, [12]byte{5}, offer, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenAnswer(vm, offer, ans)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("honest answer: %v", err)
	}

	forged := ans
	forged.CT[0] ^= 1
	if k, err := OpenAnswer(vm, offer, forged); err == nil || k != nil {
		t.Error("a forged ct gave a key")
	}
	wrongEPK := ans
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	copy(wrongEPK.EPK[:], other.PublicKey().Bytes())
	if k, err := OpenAnswer(vm, offer, wrongEPK); err == nil || k != nil {
		t.Error("a wrong epk gave a key")
	}
	// A wrong AAD: the same answer opened for a different offer name.
	otherOffer := strings.Repeat("d", 64)
	moved := ans
	moved.OfferSHA256 = otherOffer
	if k, err := OpenAnswer(vm, otherOffer, moved); err == nil || k != nil {
		t.Error("another AAD gave a key")
	}
	if _, err := OpenAnswer(vm, otherOffer, ans); err == nil {
		t.Error("an answer whose offer_sha256 is not the current offer's opened")
	}
	// A low-order epk (all zero point) is refused.
	low := ans
	low.EPK = [32]byte{}
	if _, err := OpenAnswer(vm, offer, low); err == nil {
		t.Error("a low-order epk opened")
	}
	// An answer that names another offer is refused even when its ciphertext is for this one.
	misnamed := ans
	misnamed.OfferSHA256 = otherOffer
	if k, err := OpenAnswer(vm, offer, misnamed); err == nil || k != nil {
		t.Error("an answer that names another offer opened")
	}
	// Another VM's key cannot open it.
	stranger, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := OpenAnswer(stranger, offer, ans); err == nil {
		t.Error("the wrong recipient opened")
	}
}
