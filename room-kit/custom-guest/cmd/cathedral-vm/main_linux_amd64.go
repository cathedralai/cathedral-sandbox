// Command cathedral-vm is the customer's in-guest tool, bind-mounted at /run/cathedral/bin. This PR
// has one subcommand: `recovery show`, which verify_vm.py pin runs over the attested SSH connection
// (spec r3 7.5). `slots prune` is a follow-up. It never prints the key unless run as root.
package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/snp"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmrecovery"
)

// chipID asks the chip for a report and returns its CHIP_ID field (offset 0x1a0, 64 bytes).
func chipID() ([vmrecovery.ChipBytes]byte, error) {
	var out [vmrecovery.ChipBytes]byte
	report, err := snp.Collect([64]byte{})
	if err != nil {
		return out, err
	}
	copy(out[:], report[0x1a0:0x1a0+vmrecovery.ChipBytes])
	return out, nil
}

// readRecord refuses a record file that is not root-owned and private: a customer login that is
// not root must not read R through this tool, and a planted file must not be believed.
func readRecord() ([]byte, error) {
	fd, err := syscall.Open(vmrecovery.Path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), vmrecovery.Path)
	defer f.Close()
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != 0 || st.Mode&0077 != 0 || st.Size > 1024 {
		return nil, fmt.Errorf("%s must be a root-only regular file", vmrecovery.Path)
	}
	buf := make([]byte, st.Size)
	if _, err = f.ReadAt(buf, 0); err != nil {
		return nil, err
	}
	return buf, nil
}

func run(args []string, uid int) ([]byte, error) {
	if uid != 0 {
		return nil, fmt.Errorf("root required: sudo cathedral-vm recovery show")
	}
	if len(args) != 2 || args[0] != "recovery" || args[1] != "show" {
		return nil, fmt.Errorf("usage: cathedral-vm recovery show")
	}
	raw, err := readRecord()
	if err != nil {
		return nil, err
	}
	rec, err := vmrecovery.Parse(raw)
	if err != nil {
		return nil, err
	}
	chip, err := chipID()
	if err != nil {
		return nil, err
	}
	return vmrecovery.Show(rec, chip)
}

func main() {
	out, err := run(os.Args[1:], os.Geteuid())
	if err != nil {
		fmt.Fprintln(os.Stderr, "cathedral-vm:", err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(out)
}
