package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

const goodPin = "0101010101010101010101010101010101010101010101010101010101010101"

type recorder struct {
	calls    []string
	poweroff int
	execRan  int
	runDir   string // stands in for /run/cathedral
}

type fakeReady struct {
	r   *recorder
	err error
}

func (f fakeReady) Exec() error {
	f.r.execRan++
	return f.err
}

var errFault = errors.New("injected fault")

// stagesFor returns stages that fail at the named stage ("" for none).
func (r *recorder) stagesFor(faultAt string) stages {
	step := func(name string) error {
		r.calls = append(r.calls, name)
		if name == faultAt {
			return errFault
		}
		return nil
	}
	return stages{
		views: func() error { return step("views") },
		launch: func() (bootstrap.Launch, error) {
			return bootstrap.Launch{}, step("launch")
		},
		memory: func(bootstrap.Launch) error { return step("memory") },
		prepare: func(bootstrap.Launch, [32]byte, [32]byte) (execer, error) {
			if err := step("prepare"); err != nil {
				return nil, err
			}
			// The real stage writes the RAM keys here; only a full pass may do so.
			if err := os.WriteFile(filepath.Join(r.runDir, "ssh_host_ed25519_key"), []byte("k"), 0600); err != nil {
				return nil, err
			}
			if faultAt == "exec" {
				return fakeReady{r, errFault}, nil
			}
			return fakeReady{r, nil}, nil
		},
		poweroff: func() { r.poweroff++ },
		logf:     func(string, ...any) {},
	}
}

func newRecorder(t *testing.T) *recorder {
	return &recorder{runDir: t.TempDir()}
}

func entries(t *testing.T, dir string) int {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(list)
}

func TestFaultAtEachStagePowersOff(t *testing.T) {
	order := []string{"views", "launch", "memory", "prepare", "exec"}
	for i, fault := range order {
		t.Run(fault, func(t *testing.T) {
			r := newRecorder(t)
			boot(r.stagesFor(fault), goodPin, goodPin)
			if r.poweroff != 1 {
				t.Fatalf("poweroff requested %d times", r.poweroff)
			}
			// Stages after the fault never run.
			want := order[:i+1]
			if fault == "exec" {
				want = order[:4]
			}
			if strings.Join(r.calls, ",") != strings.Join(want, ",") {
				t.Fatalf("stages ran %v, want %v", r.calls, want)
			}
			if fault != "exec" && r.execRan != 0 {
				t.Fatal("Exec ran after a failed stage")
			}
			if fault != "prepare" && fault != "exec" && entries(t, r.runDir) != 0 {
				t.Fatal("runtime directory written before the verified root stage")
			}
			if fault == "prepare" && entries(t, r.runDir) != 0 {
				t.Fatal("runtime directory not empty after a failed prepare")
			}
		})
	}
}

// A real Exec replaces the process. The fake returns, which production treats
// as a failure, so the only observable success is the stage order and one Exec.
func TestFullPassReachesExecOnceInOrder(t *testing.T) {
	r := newRecorder(t)
	boot(r.stagesFor(""), goodPin, goodPin)
	if r.execRan != 1 || r.poweroff != 1 {
		t.Fatalf("exec=%d poweroff=%d (a returning Exec must power off)", r.execRan, r.poweroff)
	}
	if entries(t, r.runDir) != 1 {
		t.Fatal("full pass should have written the runtime key")
	}
	if strings.Join(r.calls, ",") != "views,launch,memory,prepare" {
		t.Fatalf("stage order %v", r.calls)
	}
}

func TestMissingOrBadPinRefusesBeforeAnyStage(t *testing.T) {
	for name, pins := range map[string][2]string{
		"unlinked verity": {"", goodPin},
		"unlinked report": {goodPin, ""},
		"zero pin":        {strings.Repeat("0", 64), goodPin},
		"short":           {goodPin[:62], goodPin},
		"uppercase":       {strings.Repeat("AB", 32), goodPin},
		"not hex":         {strings.Repeat("zz", 32), goodPin},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRecorder(t)
			boot(r.stagesFor(""), pins[0], pins[1])
			if r.poweroff != 1 || len(r.calls) != 0 || r.execRan != 0 {
				t.Fatalf("poweroff=%d calls=%v exec=%d", r.poweroff, r.calls, r.execRan)
			}
		})
	}
}

func TestPanicPowersOff(t *testing.T) {
	r := newRecorder(t)
	s := r.stagesFor("")
	s.memory = func(bootstrap.Launch) error { panic("boom") }
	boot(s, goodPin, goodPin)
	if r.poweroff != 1 || r.execRan != 0 {
		t.Fatalf("poweroff=%d exec=%d", r.poweroff, r.execRan)
	}
}

func TestNilHandoffTokenPowersOff(t *testing.T) {
	r := newRecorder(t)
	s := r.stagesFor("")
	s.prepare = func(bootstrap.Launch, [32]byte, [32]byte) (execer, error) { return nil, nil }
	boot(s, goodPin, goodPin)
	if r.poweroff != 1 {
		t.Fatalf("poweroff=%d", r.poweroff)
	}
}
