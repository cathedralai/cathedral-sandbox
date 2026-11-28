package vmmailbox

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"unsafe"
)

// File is the mailbox disk. *os.File satisfies it; tests use a byte slice.
//
// The host rewrites this disk while the guest runs, so the guest must read the disk, not its page
// cache: open the device with O_DIRECT (OpenDevice does). Every read and write here is a whole 64 KiB
// slot at a 64 KiB offset in a 4 KiB aligned buffer, which O_DIRECT requires and a plain file allows.
type File interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

// Mailbox reads and writes the slots a guest init owns. The guest writes status and offer and
// reads the answer; it never writes the answer slot.
type Mailbox struct{ f File }

// New wraps an open mailbox. size is the disk's byte size, which must be exactly 1 MiB: a block
// device reports its size by seeking, so the caller measures it (Open does for an *os.File).
func New(f File, size int64) (*Mailbox, error) {
	if size != MailboxBytes {
		return nil, errors.New("vmmailbox: the mailbox disk must be exactly 1 MiB")
	}
	return &Mailbox{f: f}, nil
}

// Status is the record the init writes on every boot (7.2 step 5).
type Status struct {
	State  string
	KeyID  string
	Report []byte
}

// Offer is what a locked disk publishes while it waits for a re-wrap answer.
type Offer struct {
	VMID   string
	Pubkey [32]byte
	Nonce  [32]byte
	Report []byte
}

// Answer is the host-written envelope (7.5), already parsed. Sig is the SSHSIG blob the customer
// made over Message; the parser checks only its shape, and internal/sshsig verifies it.
type Answer struct {
	OfferSHA256 string
	EPK         [32]byte
	Nonce       [12]byte
	CT          [48]byte
	Sig         []byte
}

const directAlign = 4096

// alignedBuffer returns n bytes at a 4 KiB aligned address, for O_DIRECT.
func alignedBuffer(n int) []byte {
	raw := make([]byte, n+directAlign)
	skew := int((directAlign - uintptr(unsafe.Pointer(&raw[0]))%directAlign) % directAlign)
	return raw[skew : skew+n : skew+n]
}

func (m *Mailbox) write(offset int64, kind Kind, body []byte) error {
	plain, err := EncodeSlot(kind, body)
	if err != nil {
		return err
	}
	slot := alignedBuffer(SlotBytes)
	copy(slot, plain)
	// One write of the whole slot at its offset, then a flush (7.5 Record).
	if _, err := m.f.WriteAt(slot, offset); err != nil {
		return err
	}
	return m.f.Sync()
}

// StatusBody returns the canonical status body, refusing any value its schema refuses.
func StatusBody(s Status) ([]byte, error) {
	body := canonical(map[string]string{"schema": StatusSchema, "state": s.State, "key_id": s.KeyID, "report": b64(s.Report)})
	if _, err := ParseBody(body, KindStatus); err != nil {
		return nil, err
	}
	return body, nil
}

// OfferBody returns the canonical offer body, refusing any value its schema refuses.
func OfferBody(o Offer) ([]byte, error) {
	body := canonical(map[string]string{"schema": OfferSchema, "vm_id": o.VMID, "pubkey": b64(o.Pubkey[:]),
		"nonce": b64(o.Nonce[:]), "report": b64(o.Report)})
	if _, err := ParseBody(body, KindOffer); err != nil {
		return nil, err
	}
	return body, nil
}

func (m *Mailbox) WriteStatus(s Status) error {
	body, err := StatusBody(s)
	if err != nil {
		return err
	}
	return m.write(StatusOffset, KindStatus, body)
}

// WriteOffer publishes the offer and returns its name (the sha256 of its body), which the
// answer must echo and which is the AAD of the envelope.
func (m *Mailbox) WriteOffer(o Offer) (string, error) {
	body, err := OfferBody(o)
	if err != nil {
		return "", err
	}
	if err := m.write(OfferOffset, KindOffer, body); err != nil {
		return "", err
	}
	return BodySHA256(body), nil
}

// ZeroOffer clears the offer slot and reads it back as zero. The init calls it on every boot that
// is not waiting for an answer, so status never shows an old offer.
func (m *Mailbox) ZeroOffer() error {
	zero := alignedBuffer(SlotBytes)
	if _, err := m.f.WriteAt(zero, OfferOffset); err != nil {
		return err
	}
	if err := m.f.Sync(); err != nil {
		return err
	}
	back := alignedBuffer(SlotBytes)
	if _, err := m.f.ReadAt(back, OfferOffset); err != nil {
		return err
	}
	for _, b := range back {
		if b != 0 {
			return errors.New("vmmailbox: the offer slot did not read back as zero")
		}
	}
	return nil
}

// ReadAnswer reads the answer slot once. Any failure, of any kind (a torn read, a bad body, a
// panic in a parser), is reported as no answer: the caller polls again.
func (m *Mailbox) ReadAnswer() (ans Answer, ok bool) {
	defer func() {
		if recover() != nil {
			ans, ok = Answer{}, false
		}
	}()
	slot := alignedBuffer(SlotBytes)
	if _, err := m.f.ReadAt(slot, AnswerOffset); err != nil {
		return Answer{}, false
	}
	body, err := DecodeSlot(slot, KindAnswer)
	if err != nil || body == nil {
		return Answer{}, false
	}
	doc, err := ParseBody(body, KindAnswer)
	if err != nil {
		return Answer{}, false
	}
	return answerFrom(doc)
}

// AnswerFor is ReadAnswer that ignores an answer for any other offer: a stale answer is inert.
func (m *Mailbox) AnswerFor(offerSHA256 string) (Answer, bool) {
	ans, ok := m.ReadAnswer()
	if !ok || ans.OfferSHA256 != offerSHA256 {
		return Answer{}, false
	}
	return ans, true
}

// ReadStatus and ReadOffer exist for tests and for the init's own read-back; an empty or
// unreadable slot returns ok false.
func (m *Mailbox) ReadStatus() (doc map[string]string, ok bool) {
	return m.readDoc(StatusOffset, KindStatus)
}
func (m *Mailbox) ReadOffer() (doc map[string]string, ok bool) {
	return m.readDoc(OfferOffset, KindOffer)
}

func (m *Mailbox) readDoc(offset int64, kind Kind) (doc map[string]string, ok bool) {
	defer func() {
		if recover() != nil {
			doc, ok = nil, false
		}
	}()
	slot := alignedBuffer(SlotBytes)
	if _, err := m.f.ReadAt(slot, offset); err != nil {
		return nil, false
	}
	body, err := DecodeSlot(slot, kind)
	if err != nil || body == nil {
		return nil, false
	}
	doc, err = ParseBody(body, kind)
	return doc, err == nil
}

func answerFrom(doc map[string]string) (Answer, bool) {
	var ans Answer
	ans.OfferSHA256 = doc["offer_sha256"]
	for name, dst := range map[string][]byte{"epk": ans.EPK[:], "nonce": ans.Nonce[:], "ct": ans.CT[:]} {
		raw, err := decodeB64(doc[name])
		if err != nil || len(raw) != len(dst) {
			return Answer{}, false
		}
		copy(dst, raw)
	}
	sig, err := decodeB64(doc["sig"])
	if err != nil || len(sig) > SigMax {
		return Answer{}, false
	}
	ans.Sig = sig
	return ans, true
}

// answerDomain starts the signed message: the v2 schema and a zero byte (r4 erratum 2.2).
const answerDomain = AnswerSchema + "\x00"

// Message is what the answer's sig signs: the domain, then offer_sha256 as 32 raw bytes, epk,
// nonce and ct (154 bytes). It binds the signature to one offer and to this ciphertext.
func (a Answer) Message() ([]byte, error) {
	offer, err := hex.DecodeString(a.OfferSHA256)
	if err != nil || len(offer) != sha256.Size {
		return nil, ErrInvalid
	}
	out := make([]byte, 0, len(answerDomain)+sha256.Size+len(a.EPK)+len(a.Nonce)+len(a.CT))
	out = append(out, answerDomain...)
	out = append(out, offer...)
	out = append(out, a.EPK[:]...)
	out = append(out, a.Nonce[:]...)
	return append(out, a.CT[:]...), nil
}

// RewrapReportData is REPORT_DATA of an offer's report (7.5 step 2):
// sha512("cathedral-vm-rewrap/v1\0" || pubkey || nonce).
func RewrapReportData(pubkey, nonce [32]byte) [64]byte {
	input := append([]byte("cathedral-vm-rewrap/v1\x00"), pubkey[:]...)
	return sha512.Sum512(append(input, nonce[:]...))
}
