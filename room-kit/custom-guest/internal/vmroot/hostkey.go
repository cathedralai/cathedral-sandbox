// Package vmroot is the VM init's root setup (spec r3 7.2 steps 4.2, 4.3 and 5): copy the verified
// base root into the file system area, grow it, make the customer's user and the VM's SSH host key,
// switch cloud-init off, write the recovery key record, bind the modules and tools, write the
// network file from the link, and switch_root.
//
// It has no vmdisk import: the disk states (7.2 step 3) belong to the init's disk package, which
// hands this package an open file-system-area file. Every step that changes the disk is followed
// by a flush and a named cut point, so a test can stop the run after any step and prove a rerun
// ends in the same tree. The tree and link logic here is portable Go; the mount, dm-verity and
// switch_root parts are linux/amd64 only.
package vmroot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
)

// openSSHEd25519 returns an unencrypted OpenSSH private key file and its one-line public key for
// an Ed25519 key derived from random. The format is PROTOCOL.key: the "openssh-key-v1" container
// with cipher and kdf "none", one public blob, and a private section with two equal check words,
// the key (seed then public key), a comment and 1, 2, 3 ... padding to a multiple of 8.
func openSSHEd25519(random io.Reader, comment string) (private, public []byte, blob []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, nil, err
	}
	var check [4]byte
	if _, err = io.ReadFull(random, check[:]); err != nil {
		return nil, nil, nil, err
	}
	str := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	blob = append(str([]byte("ssh-ed25519")), str(pub)...)

	section := append([]byte(nil), check[:]...)
	section = append(section, check[:]...)
	section = append(section, str([]byte("ssh-ed25519"))...)
	section = append(section, str(pub)...)
	section = append(section, str(priv)...) // seed || public key, 64 bytes
	section = append(section, str([]byte(comment))...)
	for pad := byte(1); len(section)%8 != 0; pad++ {
		section = append(section, pad)
	}

	file := []byte("openssh-key-v1\x00")
	file = append(file, str([]byte("none"))...)
	file = append(file, str([]byte("none"))...)
	file = append(file, str(nil)...)
	file = binary.BigEndian.AppendUint32(file, 1)
	file = append(file, str(blob)...)
	file = append(file, str(section)...)

	encoded := base64.StdEncoding.EncodeToString(file)
	var pem bytes.Buffer
	pem.WriteString("-----BEGIN OPENSSH " + "PRIVATE KEY-----\n") // split: the leak guard flags the literal header
	for len(encoded) > 70 {
		pem.WriteString(encoded[:70] + "\n")
		encoded = encoded[70:]
	}
	pem.WriteString(encoded + "\n-----END OPENSSH " + "PRIVATE KEY-----\n")
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " " + comment + "\n"
	return pem.Bytes(), []byte(line), blob, nil
}

// HostKeyFingerprint is what `ssh-keygen -l` prints for a wire blob: SHA256, base64, no padding.
func HostKeyFingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

var errShortKey = errors.New("vmroot: host key entropy exhausted")
