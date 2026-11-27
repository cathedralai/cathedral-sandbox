// cathedral-rehearsal-bootcheck: the boot gate of the REHEARSAL-ONLY test initrd (AB#1008).
// It is not the reference init of spec-r9 5.6 and is never offered to customers.
//
// It lives in testdata so that ./... (go vet, go test -race in CI) skips it, while it
// still imports #776's internal bootstrap.Validate unchanged. ops/custom-guest/rehearsal-image/build.sh
// builds it by its explicit path as the binary cathedral-rehearsal-bootcheck.
//
// Steps (spec-r9 8.7 items 1, 2 and 4; item 3, HOST_DATA, is done next by
// `cathedral-attest --boot-host-data`, #776's own native report check):
//  1. read the three fw_cfg documents and /proc/cmdline;
//  2. bootstrap.Validate: canonical bytes, every field, cmdline allowlist,
//     owner from the measured cmdline, manifest hash, owner signature, HOST_DATA value;
//  3. compare the guest-observed state: online CPUs, memory, NIC MAC, disks;
//  4. write the owner's SSH key to /run/cathedral/authorized_keys and print the
//     network values and the expected HOST_DATA as KEY=VALUE lines for /init.
//
// Any error exits 1, and /init powers the guest off.
package main

import (
	"bufio"
	"encoding/hex"
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

const fwCfgDir = "sys/firmware/qemu_fw_cfg/by_name/opt/cathedral"
const gib = int64(1) << 30

var ifaceName = regexp.MustCompile(`^[a-z0-9]{1,15}$`)

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s larger than %d bytes", path, limit)
	}
	return raw, nil
}

func readTrim(path string) (string, error) {
	raw, err := readLimited(path, 4096)
	return strings.TrimSpace(string(raw)), err
}

// onlineCPUs counts the kernel's online list, for example "0-3" or "0,2-3".
func onlineCPUs(root string) (int64, error) {
	list, err := readTrim(filepath.Join(root, "sys/devices/system/cpu/online"))
	if err != nil {
		return 0, err
	}
	var count int64
	for _, part := range strings.Split(list, ",") {
		lo, hi, ranged := strings.Cut(part, "-")
		a, err1 := strconv.ParseInt(lo, 10, 64)
		b := a
		var err2 error
		if ranged {
			b, err2 = strconv.ParseInt(hi, 10, 64)
		}
		if err1 != nil || err2 != nil || b < a {
			return 0, fmt.Errorf("online CPU list %q invalid", list)
		}
		count += b - a + 1
	}
	return count, nil
}

func memTotalBytes(root string) (int64, error) {
	f, err := os.Open(filepath.Join(root, "proc/meminfo"))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0, err
			}
			return kb * 1024, nil
		}
	}
	return 0, errors.New("MemTotal not found")
}

type disk struct {
	name  string
	bytes int64
}

// disksBySerial maps a virtio-blk serial (custom-root, custom-data) to its disks.
func disksBySerial(root string) (map[string][]disk, error) {
	entries, err := os.ReadDir(filepath.Join(root, "sys/block"))
	if err != nil {
		return nil, err
	}
	result := map[string][]disk{}
	for _, entry := range entries {
		dir := filepath.Join(root, "sys/block", entry.Name())
		serial, err := readTrim(filepath.Join(dir, "serial"))
		if err != nil {
			continue // not a virtio-blk disk (loop, ram)
		}
		sectors, err := readTrim(filepath.Join(dir, "size"))
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(sectors, 10, 64)
		if err != nil {
			return nil, err
		}
		result[serial] = append(result[serial], disk{entry.Name(), n * 512})
	}
	return result, nil
}

// nicByMAC returns the one non-loopback interface; its MAC must be the signed one.
//
// sit0 is the only other interface allowed, and only as the device-less fallback tunnel
// that a kernel with CONFIG_IPV6_SIT=y (the #776 reference kernel recipe) makes at boot.
// It is never brought up. Any other interface, or a sit0 backed by a device, refuses.
func nicByMAC(root, mac string) (string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "sys/class/net"))
	if err != nil {
		return "", err
	}
	var nics []string
	match := ""
	for _, entry := range entries {
		if entry.Name() == "lo" {
			continue
		}
		if entry.Name() == "sit0" {
			if _, err := os.Lstat(filepath.Join(root, "sys/class/net/sit0/device")); errors.Is(err, os.ErrNotExist) {
				continue
			}
		}
		nics = append(nics, entry.Name())
		addr, err := readTrim(filepath.Join(root, "sys/class/net", entry.Name(), "address"))
		if err != nil {
			return "", err
		}
		if addr == mac {
			match = entry.Name()
		}
	}
	if len(nics) != 1 || match == "" {
		return "", fmt.Errorf("want exactly one NIC with MAC %s, found %v", mac, nics)
	}
	if !ifaceName.MatchString(match) {
		return "", fmt.Errorf("interface name %q refused", match)
	}
	return match, nil
}

func run(root string, out io.Writer) error {
	docs := map[string][]byte{}
	for _, name := range []string{"manifest.json", "bootstrap.json", "bootstrap.sig"} {
		raw, err := readLimited(filepath.Join(root, fwCfgDir, name, "raw"), 16384)
		if err != nil {
			return fmt.Errorf("fw_cfg %s: %w", name, err)
		}
		docs[name] = raw
	}
	cmdline, err := readLimited(filepath.Join(root, "proc/cmdline"), 4096)
	if err != nil {
		return err
	}
	launch, err := bootstrap.Validate(docs["manifest.json"], docs["bootstrap.json"], docs["bootstrap.sig"], string(cmdline))
	if err != nil {
		return fmt.Errorf("launch documents refused: %w", err)
	}
	m, b := launch.Manifest, launch.Bootstrap

	cpus, err := onlineCPUs(root)
	if err != nil {
		return err
	}
	if cpus != m.VCPUs {
		return fmt.Errorf("online CPUs %d, manifest vcpus %d", cpus, m.VCPUs)
	}
	// MemTotal is RAM minus what the kernel reserves (its image, the SNP
	// swiotlb bounce pool of about 6%, firmware areas), so it is below mem_gib
	// but well above the next smaller whole size.
	mem, err := memTotalBytes(root)
	if err != nil {
		return err
	}
	if mem > m.MemGiB*gib || mem*4 < m.MemGiB*gib*3 {
		return fmt.Errorf("MemTotal %d bytes does not match mem_gib %d", mem, m.MemGiB)
	}
	disks, err := disksBySerial(root)
	if err != nil {
		return err
	}
	if len(disks["custom-root"]) != 1 {
		return fmt.Errorf("want exactly one custom-root disk, found %d", len(disks["custom-root"]))
	}
	data := disks["custom-data"]
	if m.DataDiskGiB == 0 && len(data) != 0 {
		return errors.New("a custom-data disk is present but data_disk_gib is 0")
	}
	if m.DataDiskGiB != 0 && (len(data) != 1 || data[0].bytes != m.DataDiskGiB*gib) {
		return fmt.Errorf("custom-data disk does not match data_disk_gib %d", m.DataDiskGiB)
	}
	iface, err := nicByMAC(root, b.Network.GuestMAC)
	if err != nil {
		return err
	}
	if b.Ports[0].Guest != 22 {
		return errors.New("ports[0].guest must be 22")
	}

	keys := filepath.Join(root, "run/cathedral")
	if err = os.MkdirAll(keys, 0o700); err != nil {
		return err
	}
	if err = os.Chmod(keys, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(keys, "authorized_keys"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(b.SSHPublicKey + "\n"); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	// Every value below passed bootstrap.Validate or the regexp above, so it is shell safe.
	fmt.Fprintf(out, "SMOKE_LAUNCH_ID=%s\nSMOKE_HOTEL=%s\nSMOKE_IFACE=%s\nSMOKE_GUEST_IP=%s\nSMOKE_HOST_IP=%s\nSMOKE_PREFIX=%d\nSMOKE_HOST_DATA=%s\n",
		b.LaunchID, b.Hotel, iface, b.Network.GuestIP, b.Network.HostIP, b.Network.Prefix, hex.EncodeToString(launch.HostData[:]))
	return nil
}

func main() {
	if len(os.Args) != 1 || os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "usage: cathedral-rehearsal-bootcheck (as root, no arguments)")
		os.Exit(2)
	}
	if err := run("/", os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "rehearsal-bootcheck: FAIL:", err)
		os.Exit(1)
	}
}
