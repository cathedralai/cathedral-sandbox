// Command cathedral-vm-init is /init of the sealed VM initrd (AB#999, spec
// r3 7.2, "VM initrd mode"). It loads the boot modules, checks the identity
// the measured cmdline names against fw_cfg and a fresh report's HOST_DATA
// before it opens any disk, derives the root disk key from the chip,
// classifies and if allowed formats or opens the root disk (internal/vmdisk),
// hands a ready file system to the root setup, writes the mailbox status
// record and switch_roots. Any failure powers off. Nothing runs the
// customer's root before the disk's meta says ready.
//
// It is linux/amd64 only (boot_linux_amd64.go); this file carries the
// package doc so the untagged-build test runs on any host.
package main
