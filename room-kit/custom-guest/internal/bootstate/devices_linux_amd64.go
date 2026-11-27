// Package bootstate checks guest-observed devices before the reference init uses
// signed launch fields. This is only the device portion of the boot gate.
package bootstate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

type Devices struct {
	Root      string
	Data      string
	Interface string
}

var diskName = regexp.MustCompile(`^vd[a-z]+$`)
var volatileDisk = regexp.MustCompile(`^(loop|ram)[0-9]+$`)
var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

// attribute bounds every sysfs read. Sysfs directory symlinks are intentional;
// the caller must have mounted a fresh kernel sysfs, not a guest-supplied tree.
func attribute(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a sysfs attribute")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", err
	}
	if len(raw) == 0 || len(raw) > 4096 {
		return "", errors.New("invalid sysfs attribute size")
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("invalid sysfs attribute")
	}
	return value, nil
}

func decimal(raw string) (int64, error) {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != raw {
		return 0, errors.New("invalid decimal attribute")
	}
	return n, nil
}

// onlineCount parses the kernel cpulist format, rejecting overlap, duplicate
// CPUs, invalid ranges and inputs beyond the reference launch's resource cap.
func onlineCount(raw string) (int64, error) {
	var total int64
	previous := int64(-1)
	for _, part := range strings.Split(raw, ",") {
		ends := strings.Split(part, "-")
		if len(ends) < 1 || len(ends) > 2 {
			return 0, errors.New("invalid CPU range")
		}
		first, err := decimal(ends[0])
		if err != nil {
			return 0, err
		}
		last := first
		if len(ends) == 2 {
			last, err = decimal(ends[1])
			if err != nil {
				return 0, err
			}
		}
		if first <= previous || last < first || last > 4095 || last-first+1 > 56-total {
			return 0, errors.New("invalid CPU set")
		}
		total += last - first + 1
		previous = last
	}
	return total, nil
}

func driver(path, expected string) error {
	target, err := os.Readlink(filepath.Join(path, "device/driver"))
	if err != nil || filepath.Base(target) != expected {
		return fmt.Errorf("device driver must be %s", expected)
	}
	return nil
}

// CheckDevices requires a bootstrap.Validate result. Run before creating a dm
// mapping or bringing up any NIC. It never mounts, writes, starts networking or
// opens a data disk. A nil error is NOT a full boot approval: memory observation,
// native HOST_DATA/policy, dm-verity and verified-root checks remain mandatory.
func CheckDevices(launch bootstrap.Launch) (Devices, error) {
	return checkDevices("/sys", launch)
}

func checkDevices(sys string, launch bootstrap.Launch) (Devices, error) {
	fail := func(err error) (Devices, error) { return Devices{}, err }
	if launch.Manifest.VCPUs < 1 || launch.Manifest.VCPUs > 56 || launch.Manifest.Bytes["root.raw"] <= 0 ||
		launch.Manifest.DataDiskGiB < 0 || launch.Manifest.DataDiskGiB > 400 {
		return fail(errors.New("invalid launch resources"))
	}
	cpus, err := attribute(filepath.Join(sys, "devices/system/cpu/online"))
	if err != nil {
		return fail(err)
	}
	count, err := onlineCount(cpus)
	if err != nil {
		return fail(err)
	}
	if count != launch.Manifest.VCPUs {
		return fail(errors.New("online CPU count differs"))
	}
	entries, err := os.ReadDir(filepath.Join(sys, "block"))
	if err != nil {
		return fail(err)
	}
	if len(entries) > 128 {
		return fail(errors.New("too many block devices"))
	}
	result := Devices{}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(sys, "block", name)
		sizeRaw, err := attribute(filepath.Join(path, "size"))
		if err != nil {
			return fail(err)
		}
		sectors, err := decimal(sizeRaw)
		if err != nil || sectors > (1<<63-1)/512 {
			return fail(errors.New("invalid block size"))
		}
		if volatileDisk.MatchString(name) && sectors == 0 {
			continue
		}
		if !diskName.MatchString(name) {
			return fail(errors.New("unexpected block device"))
		}
		if err := driver(path, "virtio_blk"); err != nil {
			return fail(err)
		}
		serial, err := attribute(filepath.Join(path, "serial"))
		if err != nil {
			return fail(err)
		}
		ro, err := attribute(filepath.Join(path, "ro"))
		if err != nil {
			return fail(err)
		}
		switch serial {
		case "custom-root":
			if result.Root != "" || ro != "1" || sectors*512 != launch.Manifest.Bytes["root.raw"] {
				return fail(errors.New("root disk absent, duplicate, writable or wrong size"))
			}
			result.Root = "/dev/" + name
		case "custom-data":
			if result.Data != "" || launch.Manifest.DataDiskGiB == 0 || ro != "0" || sectors*512 != launch.Manifest.DataDiskGiB*(1<<30) {
				return fail(errors.New("data disk unexpected, duplicate, readonly or wrong size"))
			}
			result.Data = "/dev/" + name
		default:
			return fail(errors.New("unexpected disk serial"))
		}
	}
	if result.Root == "" || (result.Data == "") != (launch.Manifest.DataDiskGiB == 0) {
		return fail(errors.New("required disk missing"))
	}
	nics, err := os.ReadDir(filepath.Join(sys, "class/net"))
	if err != nil {
		return fail(err)
	}
	if len(nics) > 3 {
		return fail(errors.New("unexpected network devices"))
	}
	for _, nic := range nics {
		name := nic.Name()
		path := filepath.Join(sys, "class/net", name)
		if name == "lo" {
			continue
		}
		if !interfaceName.MatchString(name) || result.Interface != "" {
			return fail(errors.New("unexpected network device"))
		}
		if err := driver(path, "virtio_net"); err != nil {
			return fail(err)
		}
		mac, err := attribute(filepath.Join(path, "address"))
		if err != nil {
			return fail(err)
		}
		if mac != launch.Bootstrap.Network.GuestMAC {
			return fail(errors.New("NIC MAC differs"))
		}
		result.Interface = name
	}
	if result.Interface == "" {
		return fail(errors.New("NIC missing"))
	}
	return result, nil
}
