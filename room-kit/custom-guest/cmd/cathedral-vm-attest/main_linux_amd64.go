// Command cathedral-vm-attest is packed into the VM initrd and bind-mounted at
// /run/cathedral/bin/cathedral-attest. verify_vm.py runs it over SSH with a challenge:
// sudo -n /run/cathedral/bin/cathedral-attest CHALLENGE_HEX. It hashes the persistent
// /etc/ssh/ssh_host_ed25519_key.pub, so REPORT_DATA binds the key OpenSSH verified on that
// same connection. The customer is root in the VM and could replace this tool; that only affects
// their own VM (spec r3 6.4).
package main

import (
	"encoding/json"
	"os"
	"syscall"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/snp"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmattest"
)

// readHostKey opens the file without following links and requires a root-owned regular file that
// no one else can write, so a non-root login cannot swap the key between the read and the report.
func readHostKey() ([]byte, error) {
	fd, err := syscall.Open(vmattest.HostKeyPath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), vmattest.HostKeyPath)
	defer f.Close()
	var meta syscall.Stat_t
	if err = syscall.Fstat(fd, &meta); err != nil {
		return nil, err
	}
	if meta.Mode&syscall.S_IFMT != syscall.S_IFREG || meta.Uid != 0 || meta.Mode&0022 != 0 || meta.Size > 4096 {
		return nil, os.ErrPermission
	}
	buf := make([]byte, meta.Size)
	if _, err = f.ReadAt(buf, 0); err != nil && meta.Size != 0 {
		return nil, err
	}
	return buf, nil
}

func main() {
	answer, err := vmattest.Run(os.Args[1:], os.Geteuid(), readHostKey, snp.Collect)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": "vm_report_failed", "reason": err.Error()})
		os.Exit(1)
	}
	out, err := vmattest.Encode(answer)
	if err != nil {
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(out)
}
