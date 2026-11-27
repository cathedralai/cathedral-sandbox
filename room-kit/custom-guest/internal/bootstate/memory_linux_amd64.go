package bootstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

// memoryTolerance is the largest amount of the signed memory size the guest
// may be unable to see as System RAM (SWIOTLB, firmware and kernel carve-outs).
// A host-side shrink beyond this is refused. Measured deficit on an 8 GiB
// guest was 5.6 MiB, so this keeps a wide margin without admitting a cut.
const memoryTolerance = 128 << 20

const maxMemoryEntries = 4096

type ramRange struct{ start, end uint64 } // end is inclusive, as in sysfs

func hexAddress(raw string) (uint64, error) {
	if !strings.HasPrefix(raw, "0x") || len(raw) < 3 || len(raw) > 18 {
		return 0, errors.New("invalid memory address")
	}
	n, err := strconv.ParseUint(raw[2:], 16, 64)
	if err != nil {
		return 0, errors.New("invalid memory address")
	}
	return n, nil
}

// CheckMemory is spec 8.7 errata (27 Nov): S is the sum of end-start+1 over
// /sys/firmware/memmap entries of type exactly "System RAM", and must satisfy
// mem_gib*2^30 - 128 MiB <= S <= mem_gib*2^30. MemTotal is not used, because it
// subtracts SWIOTLB and kernel reservations. A missing or unparseable
// inventory, or overlapping RAM entries, refuse. Run after ReadBoundLaunch and
// before PrepareVerifiedRuntime. The kernel needs CONFIG_FIRMWARE_MEMMAP=y.
func CheckMemory(launch bootstrap.Launch) error {
	return checkMemory("/sys/firmware/memmap", launch.Manifest.MemGiB)
}

func checkMemory(memmap string, memGiB int64) error {
	if memGiB < 1 || memGiB > 4096 {
		return errors.New("invalid signed memory size")
	}
	entries, err := os.ReadDir(memmap)
	if err != nil {
		return fmt.Errorf("memory map unavailable: %w", err)
	}
	if len(entries) == 0 || len(entries) > maxMemoryEntries {
		return errors.New("memory map entry count invalid")
	}
	var ram []ramRange
	for _, entry := range entries {
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			return errors.New("memory map entry name invalid")
		}
		dir := filepath.Join(memmap, entry.Name())
		kind, err := attribute(filepath.Join(dir, "type"))
		if err != nil {
			return fmt.Errorf("memory map type: %w", err)
		}
		startRaw, err := attribute(filepath.Join(dir, "start"))
		if err != nil {
			return fmt.Errorf("memory map start: %w", err)
		}
		endRaw, err := attribute(filepath.Join(dir, "end"))
		if err != nil {
			return fmt.Errorf("memory map end: %w", err)
		}
		start, err := hexAddress(startRaw)
		if err != nil {
			return err
		}
		end, err := hexAddress(endRaw)
		if err != nil {
			return err
		}
		if end < start {
			return errors.New("memory map range inverted")
		}
		if kind == "System RAM" {
			ram = append(ram, ramRange{start, end})
		}
	}
	sort.Slice(ram, func(i, j int) bool { return ram[i].start < ram[j].start })
	var total uint64
	for i, r := range ram {
		if i > 0 && r.start <= ram[i-1].end {
			return errors.New("overlapping System RAM entries")
		}
		size := r.end - r.start + 1
		if size == 0 || total > 1<<62 {
			return errors.New("memory map size overflow")
		}
		total += size
	}
	want := uint64(memGiB) << 30
	if total > want || total < want-memoryTolerance {
		return errors.New("observed memory differs from signed launch")
	}
	return nil
}
