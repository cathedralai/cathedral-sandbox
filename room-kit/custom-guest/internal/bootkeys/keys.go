// Package bootkeys prepares the reference init's volatile SSH material.
// Call only after signed launch, observed hardware and HOST_DATA checks pass.
// The caller must write these files root-owned, mode 0600, into a new 0700 tmpfs
// directory. Nothing in this package writes a key to disk or starts networking.
package bootkeys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

func wire(data []byte) []byte {
	result := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint32(result, uint32(len(data)))
	return append(result, data...)
}

// Files encodes an unencrypted OpenSSH Ed25519 host key for RAM-only storage.
// There is no fallback if the kernel's cryptographic randomness is unavailable.
func Files(launch bootstrap.Launch, iface string, random io.Reader) (map[string][]byte, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`).MatchString(iface) || iface == "lo" {
		return nil, errors.New("invalid observed network interface")
	}
	n := launch.Bootstrap.Network
	guest, err := netip.ParseAddr(n.GuestIP)
	if err != nil || !guest.Is4() || guest.String() != n.GuestIP {
		return nil, errors.New("invalid guest address")
	}
	host, err := netip.ParseAddr(n.HostIP)
	if err != nil || !host.Is4() || host.String() != n.HostIP || host == guest || n.Prefix != 30 ||
		!netip.PrefixFrom(guest, 30).Contains(host) {
		return nil, errors.New("invalid gateway")
	}
	key := launch.Bootstrap.SSHPublicKey
	parts := strings.Split(key, " ")
	if len(parts) != 2 || strings.ContainsAny(key, "\r\n\t") || len(key) > 16384 ||
		!regexp.MustCompile(`^[a-zA-Z0-9@._+-]+$`).MatchString(parts[0]) {
		return nil, errors.New("invalid owner SSH key")
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil || base64.StdEncoding.EncodeToString(blob) != parts[1] ||
		!bytes.HasPrefix(blob, wire([]byte(parts[0]))) || len(blob) <= len(wire([]byte(parts[0]))) {
		return nil, errors.New("invalid owner SSH key encoding")
	}
	public, private, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("host key entropy: %w", err)
	}
	defer clear(private)
	var check [4]byte
	if _, err = io.ReadFull(random, check[:]); err != nil {
		return nil, fmt.Errorf("key encoding entropy: %w", err)
	}
	publicBlob := append(wire([]byte("ssh-ed25519")), wire(public)...)
	secret := append(append([]byte{}, check[:]...), check[:]...)
	secret = append(secret, wire([]byte("ssh-ed25519"))...)
	secret = append(secret, wire(public)...)
	secret = append(secret, wire(private)...)
	secret = append(secret, wire(nil)...)
	for pad := byte(1); len(secret)%8 != 0; pad++ {
		secret = append(secret, pad)
	}
	encoded := []byte("openssh-key-v1\x00")
	encoded = append(encoded, wire([]byte("none"))...)
	encoded = append(encoded, wire([]byte("none"))...)
	encoded = append(encoded, wire(nil)...)
	encoded = append(encoded, 0, 0, 0, 1)
	encoded = append(encoded, wire(publicBlob)...)
	encoded = append(encoded, wire(secret)...)
	result := map[string][]byte{
		"ssh_host_ed25519_key":     pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: encoded}),
		"ssh_host_ed25519_key.pub": []byte("ssh-ed25519 " + base64.StdEncoding.EncodeToString(publicBlob) + "\n"),
		"authorized_keys":          []byte(key + "\n"),
		"network.env":              []byte(fmt.Sprintf("CATHEDRAL_INTERFACE=%s\nCATHEDRAL_GUEST_CIDR=%s/%d\nCATHEDRAL_GATEWAY=%s\n", iface, n.GuestIP, n.Prefix, n.HostIP)),
	}
	clear(encoded)
	clear(secret)
	return result, nil
}
