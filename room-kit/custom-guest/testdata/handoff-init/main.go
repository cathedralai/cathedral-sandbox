package main

import (
	"fmt"
	"os"
	"syscall"
)

func fail(s string) { fmt.Fprintln(os.Stderr, s); os.Exit(1) }
func main() {
	for fd := 3; fd < 256; fd++ {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno == 0 {
			p, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
			fail(fmt.Sprintf("descriptor %d present: %s", fd, p))
		}
	}
	if os.Getpid() != 1 {
		fail("not PID1")
	}
	if len(os.Args) != 1 || os.Args[0] != "/sbin/init" {
		fail("unexpected arguments")
	}
	if len(os.Environ()) != 3 || os.Getenv("PATH") != "/usr/sbin:/usr/bin:/sbin:/bin" || os.Getenv("LANG") != "C" || os.Getenv("TERM") != "linux" {
		fail("environment leaked")
	}
	for _, p := range []string{"/dev/handoff-dev", "/sys/handoff-sys", "/run/handoff-run"} {
		b, e := os.ReadFile(p)
		if e != nil || string(b) != "synthetic fixture\n" {
			fail("mount handoff failed")
		}
	}
	if _, e := os.Stat("/old-root-only"); !os.IsNotExist(e) {
		fail("old root visible")
	}
	if _, e := os.Stat("/proc/self/status"); e != nil {
		fail("proc not moved")
	}
	var fs syscall.Statfs_t
	if e := syscall.Statfs("/", &fs); e != nil || fs.Flags&syscall.MS_RDONLY == 0 {
		fail("root not read-only")
	}
	fmt.Println("PASS: isolated PID1 root switch; dev/sys/proc/run preserved; old root absent; fixed environment; no inherited descriptors")
}
