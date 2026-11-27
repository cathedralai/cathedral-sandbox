package vmdisk

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
)

// fakeFacts answers the classifier's probes and records which ran.
type fakeFacts struct {
	intent  IntentStatus
	kind    HeaderKind
	header  Header
	opens   bool
	meta    Current
	blank   bool
	failAt  string
	calls   []string
	askedOn []int
}

var errProbe = errors.New("probe failed")

func (f *fakeFacts) step(name string) error {
	f.calls = append(f.calls, name)
	if f.failAt == name {
		return errProbe
	}
	return nil
}

func (f *fakeFacts) Intent() (IntentStatus, error) { return f.intent, f.step("intent") }
func (f *fakeFacts) Header() (HeaderKind, Header, error) {
	return f.kind, f.header, f.step("header")
}
func (f *fakeFacts) Opens(slots []int) (int, bool, error) {
	f.askedOn = slots
	if err := f.step("opens"); err != nil {
		return -1, false, err
	}
	if !f.opens {
		return -1, false, nil
	}
	return 3, true, nil
}
func (f *fakeFacts) Meta(int) (Current, error) { return f.meta, f.step("meta") }
func (f *fakeFacts) Blank() (bool, error)      { return f.blank, f.step("blank") }

func testIdentity(t *testing.T, vmID string) vmidentity.Identity {
	t.Helper()
	raw := `{"base_root_data_bytes":8192,"base_root_verity":"1111111111111111111111111111111111111111111111111111111111111111",` +
		`"salt_hex":"000102030405060708090a0b0c0d0e0f","schema":"cathedral.vm.identity/v1",` +
		`"ssh_public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/","version":1,"vm_id":"` + vmID + `"}`
	id, err := vmidentity.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestClassifyEveryBranch(t *testing.T) {
	id := testIdentity(t, "vm-0123456789ab")
	other := testIdentity(t, "vm-ba9876543210")
	ours := Current{Valid: true, Meta: Meta{Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), State: StateReady}}
	theirs := Current{Valid: true, Meta: Meta{Seq: 1, VMID: other.VMID, IdentitySHA256: other.SHA256Hex(), State: StateReady}}
	good := Header{Parsed: true, Keyslots: []int{0, 3}, RulesOK: true}
	failing := Header{Parsed: true, Keyslots: []int{3}}
	noSlots := Header{Parsed: true, Keyslots: []int{}}
	unparsed := Header{}

	cases := []struct {
		name  string
		facts fakeFacts
		want  State
		calls []string
	}{
		{"blank, no intent", fakeFacts{kind: NoLUKS2, blank: true}, StateNew, []string{"intent", "header", "blank"}},
		{"blank, foreign intent", fakeFacts{intent: IntentForeign, kind: NoLUKS2, blank: true}, StateNew, []string{"intent", "header", "blank"}},
		{"nonblank, no intent", fakeFacts{kind: NoLUKS2}, StateBroken, []string{"intent", "header", "blank"}},
		{"nonblank, foreign intent", fakeFacts{intent: IntentForeign, kind: NoLUKS2}, StateBroken, []string{"intent", "header", "blank"}},
		{"no LUKS2, intent", fakeFacts{intent: IntentValid, kind: NoLUKS2}, StateResume, []string{"intent", "header"}},
		{"LUKS1, no intent", fakeFacts{kind: LUKS1, blank: true}, StateBroken, []string{"intent", "header"}},
		{"LUKS1, intent", fakeFacts{intent: IntentValid, kind: LUKS1}, StateBroken, []string{"intent", "header"}},
		{"unreadable LUKS magic, no intent", fakeFacts{kind: Unreadable, blank: true}, StateBroken, []string{"intent", "header"}},
		{"unreadable LUKS magic, intent", fakeFacts{intent: IntentValid, kind: Unreadable}, StateBroken, []string{"intent", "header"}},
		{"rules fail, no intent", fakeFacts{kind: LUKS2, header: failing, opens: true, meta: ours}, StateTampered, []string{"intent", "header"}},
		{"rules fail, foreign intent", fakeFacts{intent: IntentForeign, kind: LUKS2, header: failing, opens: true}, StateTampered, []string{"intent", "header"}},
		{"unparsed, no intent", fakeFacts{kind: LUKS2, header: unparsed, opens: true}, StateTampered, []string{"intent", "header"}},
		{"locked", fakeFacts{kind: LUKS2, header: good}, StateLocked, []string{"intent", "header", "opens"}},
		{"locked, foreign intent", fakeFacts{intent: IntentForeign, kind: LUKS2, header: good}, StateLocked, []string{"intent", "header", "opens"}},
		{"open", fakeFacts{kind: LUKS2, header: good, opens: true, meta: ours}, StateOpen, []string{"intent", "header", "opens", "meta"}},
		{"open, intent", fakeFacts{intent: IntentValid, kind: LUKS2, header: good, opens: true, meta: ours}, StateOpen, []string{"intent", "header", "opens", "meta"}},
		{"meta of another identity", fakeFacts{kind: LUKS2, header: good, opens: true, meta: theirs}, StateBroken, []string{"intent", "header", "opens", "meta"}},
		{"meta of another identity, intent", fakeFacts{intent: IntentValid, kind: LUKS2, header: good, opens: true, meta: theirs}, StateBroken, []string{"intent", "header", "opens", "meta"}},
		{"opens, no meta, no intent", fakeFacts{kind: LUKS2, header: good, opens: true}, StateBroken, []string{"intent", "header", "opens", "meta"}},
		{"opens, no meta, intent", fakeFacts{intent: IntentValid, kind: LUKS2, header: good, opens: true}, StateResume, []string{"intent", "header", "opens", "meta"}},
		{"foreign slot, intent", fakeFacts{intent: IntentValid, kind: LUKS2, header: good}, StateBroken, []string{"intent", "header", "opens"}},
		{"rules fail, no keyslot, intent", fakeFacts{intent: IntentValid, kind: LUKS2, header: noSlots, opens: true}, StateResume, []string{"intent", "header"}},
		{"rules fail, our slot, no meta, intent", fakeFacts{intent: IntentValid, kind: LUKS2, header: failing, opens: true}, StateResume, []string{"intent", "header", "opens", "meta"}},
		{"rules fail, foreign slot, intent", fakeFacts{intent: IntentValid, kind: LUKS2, header: failing}, StateBroken, []string{"intent", "header", "opens"}},
		{"rules fail, committed meta, intent", fakeFacts{intent: IntentValid, kind: LUKS2, header: failing, opens: true, meta: ours}, StateBroken, []string{"intent", "header", "opens", "meta"}},
		{"unparsed, our slot, intent", fakeFacts{intent: IntentValid, kind: LUKS2, header: unparsed, opens: true}, StateResume, []string{"intent", "header", "opens", "meta"}},
		{"unparsed, foreign slot, intent", fakeFacts{intent: IntentValid, kind: LUKS2, header: unparsed}, StateBroken, []string{"intent", "header", "opens"}},
	}
	for _, c := range cases {
		f := c.facts
		r, err := Classify(&f, id)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if r.State != c.want {
			t.Errorf("%s: %s, want %s (%s)", c.name, r.State, c.want, r.Why)
		}
		if !reflect.DeepEqual(f.calls, c.calls) {
			t.Errorf("%s: probes %v, want %v", c.name, f.calls, c.calls)
		}
		if r.State == StateOpen && r.Slot != 3 {
			t.Errorf("%s: slot %d", c.name, r.Slot)
		}
		if r.State == StateOpen && !r.Meta.Valid {
			t.Errorf("%s: open without meta", c.name)
		}
	}
}

func TestClassifyAsksOnlyListedSlots(t *testing.T) {
	id := testIdentity(t, "vm-0123456789ab")
	f := fakeFacts{kind: LUKS2, header: Header{Parsed: true, Keyslots: []int{2, 7}, RulesOK: true}}
	if _, err := Classify(&f, id); err != nil || !reflect.DeepEqual(f.askedOn, []int{2, 7}) {
		t.Fatalf("asked on %v (%v)", f.askedOn, err)
	}
	f = fakeFacts{intent: IntentValid, kind: LUKS2, header: Header{}}
	if _, err := Classify(&f, id); err != nil || f.askedOn != nil {
		t.Fatalf("an unparsed header must try any slot, asked on %v", f.askedOn)
	}
}

func TestClassifyStopsAtAProbeError(t *testing.T) {
	id := testIdentity(t, "vm-0123456789ab")
	for _, at := range []string{"intent", "header", "opens", "meta", "blank"} {
		f := fakeFacts{kind: LUKS2, header: Header{Parsed: true, Keyslots: []int{0}, RulesOK: true}, opens: true, failAt: at}
		if at == "blank" {
			f.kind = NoLUKS2
		}
		r, err := Classify(&f, id)
		if !errors.Is(err, errProbe) || r.State != 0 {
			t.Errorf("%s: state %s, err %v", at, r.State, err)
		}
	}
}

func TestHostState(t *testing.T) {
	if StateResume.HostState() != "new" || StateOpen.HostState() != "open" || StateBroken.HostState() != "broken" {
		t.Fatal("host vm_state names differ")
	}
}
