package datavolume

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type testDisk struct {
	events                  []string
	header                  []byte
	fs                      string
	dirty                   bool
	fail                    string
	partial                 bool
	cancelAt                string
	cancel                  context.CancelFunc
	formats, mkfs, closes   int
	mounted                 bool
	closeSawCancellation    bool
	verifyCount, failVerify int
}

func (d *testDisk) step(name string) error {
	d.events = append(d.events, name)
	if d.cancelAt == name {
		d.cancel()
	}
	if d.fail == name {
		return errors.New("adapter may contain private details")
	}
	return nil
}
func (d *testDisk) Size() int64 { return 8192 }
func (d *testDisk) ReadAt(p []byte, off int64) (int, error) {
	if err := d.step("read"); err != nil {
		return 0, err
	}
	clear(p)
	if d.dirty {
		p[len(p)-1] = 1
	}
	return len(p), nil
}
func (d *testDisk) Header(ctx context.Context) ([]byte, error) {
	if err := d.step("header"); err != nil {
		return nil, err
	}
	if d.header == nil {
		return nil, ErrNotLUKS
	}
	return d.header, nil
}
func (d *testDisk) Format(ctx context.Context, key []byte) error {
	d.formats++
	d.header = []byte(policyFixture)
	d.dirty = true
	return d.step("format")
}
func (d *testDisk) Open(ctx context.Context, key []byte) (OwnedMapping, error) {
	err := d.step("open")
	if err != nil && !d.partial {
		return nil, err
	}
	return d, err
}
func (d *testDisk) Verify(ctx context.Context) error {
	d.verifyCount++
	if d.verifyCount == d.failVerify {
		return errors.New("mapping changed")
	}
	return d.step("verify")
}
func (d *testDisk) Filesystem(ctx context.Context) (string, error) { return d.fs, d.step("filesystem") }
func (d *testDisk) MakeFilesystem(ctx context.Context) error {
	d.mkfs++
	if err := d.step("mkfs"); err != nil {
		return err
	}
	d.fs = "ext4"
	return nil
}
func (d *testDisk) Mount(ctx context.Context) error { d.mounted = true; return d.step("mount") }
func (d *testDisk) Close(ctx context.Context) error {
	d.closes++
	d.closeSawCancellation = ctx.Err() != nil
	d.mounted = false
	return d.step("close")
}
func unlockTest(t *testing.T, ctx context.Context, d *testDisk) error {
	t.Helper()
	key := []byte("test-only-passphrase")
	err := Unlock(ctx, d, key)
	if !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("secret retained")
	}
	if err != nil && (strings.Contains(err.Error(), "test-only") || strings.Contains(err.Error(), "private details")) {
		t.Fatal("adapter details leaked")
	}
	return err
}
func TestNewAndExistingVolume(t *testing.T) {
	d := &testDisk{}
	if err := unlockTest(t, context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if d.formats != 1 || d.mkfs != 1 || !d.mounted || d.closes != 0 {
		t.Fatalf("first use state %+v", d)
	}
	want := "header,read,format,header,open,verify,mkfs,filesystem,verify,mount"
	if strings.Join(d.events, ",") != want {
		t.Fatalf("unsafe order %v", d.events)
	}
	d.mounted = false
	d.events = nil
	if err := unlockTest(t, context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if d.formats != 1 || d.mkfs != 1 || !d.mounted {
		t.Fatal("existing volume overwritten")
	}
	if strings.Join(d.events, ",") != "header,open,verify,filesystem,verify,mount" {
		t.Fatal(d.events)
	}
}
func TestExistingWorkNeverFormatted(t *testing.T) {
	for _, fs := range []string{"", "xfs", "crypto_LUKS"} {
		t.Run(fs, func(t *testing.T) {
			d := &testDisk{header: []byte(policyFixture), fs: fs, dirty: true}
			if unlockTest(t, context.Background(), d) == nil {
				t.Fatal("accepted unknown filesystem")
			}
			if d.formats != 0 || d.mkfs != 0 || d.closes != 1 || d.mounted {
				t.Fatal("existing work changed")
			}
		})
	}
	d := &testDisk{dirty: true}
	if unlockTest(t, context.Background(), d) == nil || d.formats != 0 || d.mkfs != 0 {
		t.Fatal("lost-header payload overwritten")
	}
}
func TestProbeFailureIsNotBlankEvidence(t *testing.T) {
	d := &testDisk{fail: "header"}
	if unlockTest(t, context.Background(), d) == nil || strings.Join(d.events, ",") != "header" {
		t.Fatal(d.events)
	}
	d = &testDisk{header: []byte(`{}`)}
	if unlockTest(t, context.Background(), d) == nil || strings.Join(d.events, ",") != "header" {
		t.Fatal(d.events)
	}
}
func TestInterruptedInitializationPreservedOnRetry(t *testing.T) {
	for _, failure := range []string{"format", "open", "verify", "mkfs"} {
		t.Run(failure, func(t *testing.T) {
			d := &testDisk{fail: failure}
			if unlockTest(t, context.Background(), d) == nil {
				t.Fatal("failure ignored")
			}
			formats, mkfs := d.formats, d.mkfs
			d.fail = ""
			d.events = nil
			if unlockTest(t, context.Background(), d) == nil {
				t.Fatal("incomplete old initialization treated as fresh")
			}
			if d.formats != formats || d.mkfs != mkfs || d.mounted {
				t.Fatal("retry reformatted existing volume")
			}
		})
	}
}
func TestUnlockFailuresCleanOwnedMapping(t *testing.T) {
	for _, failure := range []string{"open", "verify", "filesystem", "mount"} {
		t.Run(failure, func(t *testing.T) {
			d := &testDisk{header: []byte(policyFixture), fs: "ext4", fail: failure, partial: true}
			if unlockTest(t, context.Background(), d) == nil || d.closes != 1 || d.mounted || d.mkfs != 0 || d.formats != 0 {
				t.Fatal("unsafe failure cleanup")
			}
		})
	}
	d := &testDisk{header: []byte(policyFixture), fs: "ext4", fail: "open"}
	if unlockTest(t, context.Background(), d) == nil || d.closes != 0 {
		t.Fatal("closed an unowned map")
	}
	d = &testDisk{header: []byte(policyFixture), fs: "", fail: "close"}
	if err := unlockTest(t, context.Background(), d); err == nil || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("cleanup failure hidden: %v", err)
	}
}
func TestCancellationStopsWritesAndCleans(t *testing.T) {
	for _, stage := range []string{"header", "read", "format", "open", "verify", "mkfs", "filesystem", "mount"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d := &testDisk{cancelAt: stage, cancel: cancel}
			if !errors.Is(unlockTest(t, ctx, d), context.Canceled) {
				t.Fatal("cancellation ignored")
			}
			if d.closeSawCancellation || d.mounted {
				t.Fatal("cleanup used cancelled context or left mount")
			}
			for i, event := range d.events {
				if event == stage {
					for _, later := range d.events[i+1:] {
						if later != "close" {
							t.Fatalf("continued after cancellation %v", d.events)
						}
					}
					break
				}
			}
		})
	}
}
func TestPassphraseBoundAndErasure(t *testing.T) {
	for _, size := range []int{1, 4096} {
		raw := bytes.Repeat([]byte{'x'}, size)
		key, err := ReadPassphrase(bytes.NewReader(raw))
		if err != nil || !bytes.Equal(key, raw) {
			t.Fatal("valid raw input refused")
		}
		clear(key)
	}
	for _, size := range []int{0, 4097, 8192} {
		key, err := ReadPassphrase(bytes.NewReader(make([]byte, size)))
		if err == nil || key != nil {
			t.Fatal("invalid input accepted")
		}
	}
	key, err := ReadPassphrase(strings.NewReader("raw\n"))
	if err != nil || string(key) != "raw\n" {
		t.Fatal("password changed")
	}
	clear(key)
	key, err = ReadPassphrase(failingReader{})
	if err == nil || key != nil {
		t.Fatal("read error accepted")
	}
	for _, size := range []int{0, 4097} {
		d := &testDisk{}
		key := bytes.Repeat([]byte{'x'}, size)
		if Unlock(context.Background(), d, key) == nil || len(d.events) != 0 || !bytes.Equal(key, make([]byte, size)) {
			t.Fatal("invalid password used or retained")
		}
	}
}

type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) { copy(p, "secret"); return 6, io.ErrClosedPipe }

func TestMappingChangeBeforeMount(t *testing.T) {
	d := &testDisk{header: []byte(policyFixture), fs: "ext4", failVerify: 2}
	if unlockTest(t, context.Background(), d) == nil || d.closes != 1 || d.mounted {
		t.Fatal("changed mapping mounted")
	}
	for _, event := range d.events {
		if event == "mount" {
			t.Fatal("mount attempted")
		}
	}
}

func TestUnverifiedMappingNeverGetsFilesystem(t *testing.T) {
	d := &testDisk{fail: "verify"}
	if unlockTest(t, context.Background(), d) == nil || d.mkfs != 0 || d.closes != 1 || d.mounted {
		t.Fatal("filesystem written before active encryption was verified")
	}
}
