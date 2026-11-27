package bootstate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

func put(t *testing.T, root, path, value string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(value), 0644); err != nil {
		t.Fatal(err)
	}
}
func block(t *testing.T, root, name, serial string, size int64, ro string) {
	t.Helper()
	base := "block/" + name
	put(t, root, base+"/serial", serial)
	put(t, root, base+"/size", strconv.FormatInt(size/512, 10)+"\n")
	put(t, root, base+"/ro", ro+"\n")
	if err := os.MkdirAll(filepath.Join(root, base, "device"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/sys/bus/virtio/drivers/virtio_blk", filepath.Join(root, base, "device/driver")); err != nil {
		t.Fatal(err)
	}
}
func nic(t *testing.T, root, name, mac string) {
	t.Helper()
	base := "class/net/" + name
	put(t, root, base+"/address", mac+"\n")
	if err := os.MkdirAll(filepath.Join(root, base, "device"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/sys/bus/virtio/drivers/virtio_net", filepath.Join(root, base, "device/driver")); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T, data bool) (string, bootstrap.Launch) {
	t.Helper()
	root := t.TempDir()
	launch := bootstrap.Launch{Manifest: bootstrap.Manifest{VCPUs: 4, Bytes: map[string]int64{"root.raw": 72916992}}, Bootstrap: bootstrap.Bootstrap{Network: bootstrap.Network{GuestMAC: "52:54:00:ab:cd:ef"}}}
	put(t, root, "devices/system/cpu/online", "0-3\n")
	// Deliberately not vda: enumeration order is not a trusted disk identity.
	block(t, root, "vdb", "custom-root", launch.Manifest.Bytes["root.raw"], "1")
	if data {
		launch.Manifest.DataDiskGiB = 4
		block(t, root, "vda", "custom-data", 4<<30, "0")
	}
	put(t, root, "block/loop0/size", "0\n")
	nic(t, root, "ens3", launch.Bootstrap.Network.GuestMAC)
	if err := os.MkdirAll(filepath.Join(root, "class/net/lo"), 0755); err != nil {
		t.Fatal(err)
	}
	return root, launch
}
func TestDiskOrderAndOptionalData(t *testing.T) {
	for _, data := range []bool{false, true} {
		root, launch := fixture(t, data)
		got, err := checkDevices(root, launch)
		if err != nil {
			t.Fatal(err)
		}
		if got.Root != "/dev/vdb" || got.Interface != "ens3" || (got.Data != "/dev/vda" && data) || (got.Data != "" && !data) {
			t.Fatalf("wrong selection: %+v", got)
		}
	}
}
func TestRefusals(t *testing.T) {
	cases := map[string]func(*testing.T, string, *bootstrap.Launch){
		"cpu-count":   func(t *testing.T, r string, l *bootstrap.Launch) { put(t, r, "devices/system/cpu/online", "0-2\n") },
		"cpu-overlap": func(t *testing.T, r string, l *bootstrap.Launch) { put(t, r, "devices/system/cpu/online", "0-2,2\n") },
		"missing-cpu": func(t *testing.T, r string, l *bootstrap.Launch) {
			os.Rename(filepath.Join(r, "devices/system/cpu/online"), filepath.Join(r, "cpu-away"))
		},
		"root-writable": func(t *testing.T, r string, l *bootstrap.Launch) { put(t, r, "block/vdb/ro", "0\n") },
		"root-size":     func(t *testing.T, r string, l *bootstrap.Launch) { put(t, r, "block/vdb/size", "8\n") },
		"overflow": func(t *testing.T, r string, l *bootstrap.Launch) {
			put(t, r, "block/vdb/size", "9223372036854775807\n")
		},
		"duplicate-root": func(t *testing.T, r string, l *bootstrap.Launch) {
			block(t, r, "vdc", "custom-root", l.Manifest.Bytes["root.raw"], "1")
		},
		"missing-root":    func(t *testing.T, r string, l *bootstrap.Launch) { put(t, r, "block/vdb/serial", "unrecognized") },
		"unexpected-data": func(t *testing.T, r string, l *bootstrap.Launch) { block(t, r, "vda", "custom-data", 4<<30, "0") },
		"missing-data":    func(t *testing.T, r string, l *bootstrap.Launch) { l.Manifest.DataDiskGiB = 4 },
		"extra-disk": func(t *testing.T, r string, l *bootstrap.Launch) {
			block(t, r, "sda", "custom-root", l.Manifest.Bytes["root.raw"], "1")
		},
		"nonempty-loop": func(t *testing.T, r string, l *bootstrap.Launch) { put(t, r, "block/loop0/size", "8\n") },
		"mac": func(t *testing.T, r string, l *bootstrap.Launch) {
			put(t, r, "class/net/ens3/address", "52:54:00:00:00:00\n")
		},
		"second-nic": func(t *testing.T, r string, l *bootstrap.Launch) { nic(t, r, "eth1", l.Bootstrap.Network.GuestMAC) },
		"no-nic": func(t *testing.T, r string, l *bootstrap.Launch) {
			os.Rename(filepath.Join(r, "class/net/ens3"), filepath.Join(r, "nic-away"))
		},
		"bad-driver": func(t *testing.T, r string, l *bootstrap.Launch) {
			os.Rename(filepath.Join(r, "block/vdb/device/driver"), filepath.Join(r, "driver-away"))
			os.Symlink("/sys/bus/scsi/drivers/sd", filepath.Join(r, "block/vdb/device/driver"))
		},
		"oversize-attribute": func(t *testing.T, r string, l *bootstrap.Launch) {
			put(t, r, "block/vdb/serial", strings.Repeat("a", 4097))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r, l := fixture(t, false)
			change(t, r, &l)
			got, err := checkDevices(r, l)
			if err == nil || got != (Devices{}) {
				t.Fatalf("accepted invalid state: %+v %v", got, err)
			}
		})
	}
}
func TestDataDiskSizeAndIdentity(t *testing.T) {
	for _, which := range []string{"wrong-size", "readonly", "duplicate"} {
		t.Run(which, func(t *testing.T) {
			r, l := fixture(t, true)
			switch which {
			case "wrong-size":
				put(t, r, "block/vda/size", "1024\n")
			case "readonly":
				put(t, r, "block/vda/ro", "1\n")
			case "duplicate":
				block(t, r, "vdc", "custom-data", 4<<30, "0")
			}
			if _, err := checkDevices(r, l); err == nil {
				t.Fatal("bad data disk accepted")
			}
		})
	}
}
func TestOnlineCPUList(t *testing.T) {
	for raw, want := range map[string]int64{"0": 1, "0-55": 56, "0-1,4,6-8": 6} {
		n, err := onlineCount(raw)
		if err != nil || n != want {
			t.Fatalf("%s: %d %v", raw, n, err)
		}
	}
	for _, raw := range []string{"", "0-56", "0,0", "3-2", "1,0", "0-2,2-3", "+1", "01", "0-999999999999999999999", "0-1-2", "0,", "0\n"} {
		if _, err := onlineCount(raw); err == nil {
			t.Fatalf("bad CPU list accepted: %q", raw)
		}
	}
}
