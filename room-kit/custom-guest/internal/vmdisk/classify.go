package vmdisk

import "github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"

// State is the root disk's class for this boot (spec r3 7.2 step 3).
type State int

const (
	StateNew      State = iota + 1 // blank LUKS device: format from F1
	StateResume                    // this VM's own intent, not committed: format from F3
	StateOpen                      // committed, and the meta names this identity
	StateLocked                    // LUKS2 under our rules that no slot opens: re-wrap (7.5)
	StateTampered                  // LUKS2 that fails the VM header rules
	StateBroken                    // anything else: untouched, needs a person or a restore
)

func (s State) String() string {
	switch s {
	case StateNew:
		return "new"
	case StateResume:
		return "resume"
	case StateOpen:
		return "open"
	case StateLocked:
		return "locked"
	case StateTampered:
		return "tampered"
	case StateBroken:
		return "broken"
	}
	return "unknown"
}

// HostState is the vm_state the host shows: new also covers resume.
func (s State) HostState() string {
	if s == StateResume {
		return StateNew.String()
	}
	return s.String()
}

// HeaderKind is what a read-only probe of the LUKS device finds.
type HeaderKind int

const (
	NoLUKS2    HeaderKind = iota // no LUKS magic and no header cryptsetup reads
	LUKS1                        // a LUKS1 header: never made by this init
	LUKS2                        // a LUKS2 header cryptsetup reads
	Unreadable                   // a LUKS magic (primary or secondary) cryptsetup cannot read
)

// Facts are the read-only probes the classifier asks for, in its order. The
// Linux adapter runs them on a read-only mapping; tests use a fake that
// records which probes ran. No probe writes.
type Facts interface {
	// Intent parses the first 4 KiB of the intent area for this boot.
	Intent() (IntentStatus, error)
	// Header probes the LUKS device.
	Header() (HeaderKind, Header, error)
	// Opens tests this boot's key on the listed slots (nil: any slot) and
	// returns the first that opens.
	Opens(slots []int) (slot int, ok bool, err error)
	// Meta opens the volume read-only with that slot and reads both copies.
	Meta(slot int) (Current, error)
	// Blank reads the whole LUKS device; false on any nonzero byte or a
	// device that cannot be read to its end.
	Blank() (bool, error)
}

// Result is a classification and what it saw.
type Result struct {
	State  State
	Intent IntentStatus
	Slot   int     // the slot this key opened, or -1
	Meta   Current // valid only for StateOpen
	Why    string  // one line for the serial log; never key material
}

// Classify is spec r3 7.2 step 3 for a root.raw of diskBytes. Committed
// means: the LUKS device passes the VM header rules, a slot opens with this
// key, and a meta copy is valid.
// An error from a probe is returned as is: the caller powers off and writes
// nothing, and the disk is not classified.
//
// One rule is stricter than r3's text: with a valid intent, a header that
// fails the rules but that this key opens and that holds a valid meta copy
// is broken, not resume. That is a committed volume behind an edited header,
// so a forged intent never formats a volume this boot can read a meta from.
//
// A committed volume whose meta records another disk size than this boot's
// is broken (#805), smaller or larger: the intent area and the LUKS device
// end move with the size, so the open would treat live ciphertext as the
// intent area (smaller) or a stale tail as part of the volume (larger).
func Classify(f Facts, id vmidentity.Identity, diskBytes int64) (Result, error) {
	r := Result{Slot: -1}
	var err error
	if r.Intent, err = f.Intent(); err != nil {
		return r, err
	}
	intent := r.Intent == IntentValid
	done := func(s State, why string) (Result, error) { r.State, r.Why = s, why; return r, nil }

	kind, h, err := f.Header()
	if err != nil {
		return r, err
	}
	switch kind {
	case LUKS1:
		return done(StateBroken, "a LUKS1 header, which this init never makes")
	case Unreadable:
		// Not "no header": with an intent that would resume and format over
		// whatever volume the header held. A cut inside F3's header write can
		// leave this too; F3 runs only before any customer data exists.
		return done(StateBroken, "a LUKS header magic that cryptsetup cannot read")
	case NoLUKS2:
		if intent {
			return done(StateResume, "this VM's intent and no LUKS2 header: resume at F3")
		}
		blank, err := f.Blank()
		if err != nil {
			return r, err
		}
		if blank {
			return done(StateNew, "every byte of the LUKS device is zero")
		}
		return done(StateBroken, "not LUKS2, not blank and no intent")
	}

	if !h.RulesOK && !intent {
		return done(StateTampered, "the LUKS2 header fails the VM header rules")
	}
	if h.Parsed && len(h.Keyslots) == 0 {
		// Only reachable with an intent: a header with no keyslot fails the rules.
		return done(StateResume, "this VM's intent and a header with no keyslot: resume at F3")
	}
	var slots []int
	if h.Parsed {
		slots = h.Keyslots
	}
	slot, opens, err := f.Opens(slots)
	if err != nil {
		return r, err
	}
	if !opens {
		if intent {
			return done(StateBroken, "an intent with a keyslot this key cannot open (another bundle?): restore the old bundle")
		}
		return done(StateLocked, "no keyslot opens with this key")
	}
	r.Slot = slot
	meta, err := f.Meta(slot)
	if err != nil {
		return r, err
	}
	switch {
	case meta.Valid && !h.RulesOK:
		return done(StateBroken, "a committed volume behind a header that fails the VM header rules")
	case meta.Valid && !meta.Meta.Names(id):
		return done(StateBroken, "the volume's meta names another identity")
	case meta.Valid && meta.Meta.DiskBytes != diskBytes:
		return done(StateBroken, "the disk is not the size the volume was committed at")
	case meta.Valid:
		r.Meta = meta
		return done(StateOpen, "committed; meta "+meta.Meta.State)
	case intent:
		return done(StateResume, "this VM's intent, a slot this key opens and no meta: resume at F3")
	}
	return done(StateBroken, "a slot opens but no meta copy is valid and there is no intent")
}
