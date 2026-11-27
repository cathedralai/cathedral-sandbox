package bootkeys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

func example(t *testing.T) bootstrap.Launch {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := append(wire([]byte("ssh-ed25519")), wire(public)...)
	return bootstrap.Launch{Bootstrap: bootstrap.Bootstrap{
		SSHPublicKey: "ssh-ed25519 " + base64.StdEncoding.EncodeToString(key),
		Network:      bootstrap.Network{GuestIP: "10.217.0.2", HostIP: "10.217.0.1", Prefix: 30},
	}}
}

func TestOpenSSHReadsFreshKeyAndOwnerOnly(t *testing.T) {
	launch := example(t)
	first, err := Files(launch, "eth0", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Files(launch, "eth0", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first["ssh_host_ed25519_key.pub"], second["ssh_host_ed25519_key.pub"]) {
		t.Fatal("host key reused")
	}
	private := filepath.Join(t.TempDir(), "key")
	if err = os.WriteFile(private, first["ssh_host_ed25519_key"], 0600); err != nil {
		t.Fatal(err)
	}
	// Independent OpenSSH parser validates the private container and padding.
	// A real signature below proves the private seed matches the public key;
	// `ssh-keygen -y` alone merely reads the cached public bytes.
	decoded, err := exec.Command("ssh-keygen", "-y", "-P", "", "-f", private).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, first["ssh_host_ed25519_key.pub"]) {
		t.Fatal("OpenSSH public key differs")
	}
	payload := []byte("reference guest boot key interoperability\n")
	message := filepath.Join(filepath.Dir(private), "message")
	if err = os.WriteFile(message, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ssh-keygen", "-Y", "sign", "-f", private, "-n", "cathedral-test", message).CombinedOutput(); err != nil {
		t.Fatalf("OpenSSH signing failed: %v: %s", err, out)
	}
	allowed := filepath.Join(filepath.Dir(private), "allowed")
	if err = os.WriteFile(allowed, append([]byte("guest "), decoded...), 0600); err != nil {
		t.Fatal(err)
	}
	verify := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "guest", "-n", "cathedral-test", "-s", message+".sig")
	verify.Stdin = bytes.NewReader(payload)
	if out, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("OpenSSH signature verification failed: %v: %s", err, out)
	}
	if string(first["authorized_keys"]) != launch.Bootstrap.SSHPublicKey+"\n" {
		t.Fatal("owner key differs")
	}
	if len(first) != 4 {
		t.Fatal("unexpected runtime files")
	}
	if string(first["network.env"]) != "CATHEDRAL_INTERFACE=eth0\nCATHEDRAL_GUEST_CIDR=10.217.0.2/30\nCATHEDRAL_GATEWAY=10.217.0.1\n" {
		t.Fatal("network config differs")
	}
}

type brokenEntropy struct{}

func (brokenEntropy) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestEntropyFailureProducesNoFiles(t *testing.T) {
	files, err := Files(example(t), "eth0", brokenEntropy{})
	if err == nil || files != nil {
		t.Fatal("entropy failure accepted")
	}
}

func TestRefuseRuntimeInjection(t *testing.T) {
	cases := []struct {
		name   string
		change func(*bootstrap.Launch)
		iface  string
	}{
		{"owner newline", func(l *bootstrap.Launch) { l.Bootstrap.SSHPublicKey += "\nssh-ed25519 attacker" }, "eth0"},
		{"owner options", func(l *bootstrap.Launch) { l.Bootstrap.SSHPublicKey = "command=bad " + l.Bootstrap.SSHPublicKey }, "eth0"},
		{"gateway environment", func(l *bootstrap.Launch) { l.Bootstrap.Network.HostIP += "\nCATHEDRAL_INTERFACE=lo" }, "eth0"},
		{"guest environment", func(l *bootstrap.Launch) { l.Bootstrap.Network.GuestIP += "\"" }, "eth0"},
		{"foreign gateway", func(l *bootstrap.Launch) { l.Bootstrap.Network.HostIP = "10.217.1.1" }, "eth0"},
		{"interface environment", func(*bootstrap.Launch) {}, "eth0\nX=y"},
		{"interface option", func(*bootstrap.Launch) {}, "-dev"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := example(t)
			c.change(&l)
			files, err := Files(l, c.iface, strings.NewReader(""))
			if err == nil || files != nil || strings.Contains(err.Error(), "entropy") {
				t.Fatal("invalid runtime value reached key generation")
			}
		})
	}
}
