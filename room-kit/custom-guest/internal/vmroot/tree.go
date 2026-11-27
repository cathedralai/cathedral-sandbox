package vmroot

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmrecovery"
)

// Identity is the part of the VM identity document (6.3) this package uses. The disk package has
// already checked it against the cmdline and HOST_DATA.
type Identity struct {
	VMID           string
	IdentitySHA256 string
	SSHPublicKey   string // "<type> <base64>", no comment
}

const (
	// The user's ids. The base root has no other user at these numbers (7.3: a server package
	// set with no cloud image user); PrepareTree refuses a root that does.
	userName = "cathedral"
	userID   = 1000
	// shadow's "last changed" day is fixed so the same inputs give the same tree.
	shadowDay = "20419"
)

var keyLineRe = regexp.MustCompile(`^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]{16,1000}={0,2}$`)

// TreeOptions carries what the tree steps need. Chown is a seam: it is nil in the init (the real
// Lchown through the root) and recorded in tests, which do not run as root.
type TreeOptions struct {
	Identity Identity
	Random   io.Reader
	Chown    func(root *os.Root, name string, uid, gid int) error
	Cut      func(point string) error
}

func (o TreeOptions) chown(root *os.Root, name string, uid, gid int) error {
	if o.Chown != nil {
		return o.Chown(root, name, uid, gid)
	}
	return root.Lchown(name, uid, gid)
}

func (o TreeOptions) cut(point string) error {
	if o.Cut == nil {
		return nil
	}
	return o.Cut(point)
}

// Cut points named by this package, in the order they run. A test cuts at each and reruns.
const (
	CutUser      = "vmroot:user"
	CutHostKey   = "vmroot:hostkey"
	CutCloudInit = "vmroot:cloudinit"
	CutRecovery  = "vmroot:recovery"
)

// PrepareTree is step 4.2 after the copy and resize: the user, the SSH host key and cloud-init
// off, on a mounted pristine copy of the base root. A cut leaves a partial tree, which the next
// boot throws away by copying the base again (7.2 step 4: "repeats from step 1").
func PrepareTree(root *os.Root, o TreeOptions) error {
	if !keyLineRe.MatchString(o.Identity.SSHPublicKey) {
		return errors.New("vmroot: the identity's ssh key is not one OpenSSH public key")
	}
	if err := addUser(root, o); err != nil {
		return err
	}
	if err := o.cut(CutUser); err != nil {
		return err
	}
	if err := writeHostKey(root, o); err != nil {
		return err
	}
	if err := o.cut(CutHostKey); err != nil {
		return err
	}
	if err := AssertCloudInitOff(root); err != nil {
		return err
	}
	return o.cut(CutCloudInit)
}

// appendLine adds one line to a colon file, refusing a name or id already in it.
func appendLine(root *os.Root, name, line string, taken func(fields []string) bool) error {
	raw, err := root.ReadFile(name)
	if err != nil {
		return err
	}
	for _, existing := range strings.Split(string(raw), "\n") {
		if existing != "" && taken(strings.Split(existing, ":")) {
			return fmt.Errorf("vmroot: %s already has the user or id of %s", name, userName)
		}
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		raw = append(raw, '\n')
	}
	return root.WriteFile(name, append(raw, line+"\n"...), 0)
}

func addUser(root *os.Root, o TreeOptions) error {
	id := fmt.Sprint(userID)
	// WriteFile on an existing file truncates it and keeps its mode, so the files keep theirs.
	if err := appendLine(root, "etc/passwd", userName+":x:"+id+":"+id+":Cathedral VM user:/home/"+userName+":/bin/bash",
		func(f []string) bool { return f[0] == userName || (len(f) > 2 && f[2] == id) }); err != nil {
		return err
	}
	if err := appendLine(root, "etc/group", userName+":x:"+id+":",
		func(f []string) bool { return f[0] == userName || (len(f) > 2 && f[2] == id) }); err != nil {
		return err
	}
	if err := appendLine(root, "etc/shadow", userName+":*:"+shadowDay+":0:99999:7:::",
		func(f []string) bool { return f[0] == userName }); err != nil {
		return err
	}
	// gshadow may be absent on a minimal root; when present it must agree with group.
	if _, err := root.Lstat("etc/gshadow"); err == nil {
		if err := appendLine(root, "etc/gshadow", userName+":!::", func(f []string) bool { return f[0] == userName }); err != nil {
			return err
		}
	}
	if err := root.MkdirAll("home/"+userName+"/.ssh", 0o700); err != nil {
		return err
	}
	for _, dir := range []string{"home/" + userName, "home/" + userName + "/.ssh"} {
		if err := root.Chmod(dir, 0o700); err != nil {
			return err
		}
		if err := o.chown(root, dir, userID, userID); err != nil {
			return err
		}
	}
	keys := "home/" + userName + "/.ssh/authorized_keys"
	if err := writeNew(root, keys, []byte(o.Identity.SSHPublicKey+"\n"), 0o600); err != nil {
		return err
	}
	if err := o.chown(root, keys, userID, userID); err != nil {
		return err
	}
	// The old cloud-init config gave the user sudo without a password (f7b3ed3 vm_ctl.py make_seed);
	// verify_vm.py runs `sudo -n cathedral-attest`.
	if err := root.MkdirAll("etc/sudoers.d", 0o750); err != nil {
		return err
	}
	return writeNew(root, "etc/sudoers.d/90-cathedral", []byte(userName+" ALL=(ALL) NOPASSWD:ALL\n"), 0o440)
}

// writeNew creates name and fails if it exists: a pristine base never has these files.
func writeNew(root *os.Root, name string, data []byte, mode os.FileMode) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Chmod(name, mode) // the umask must not narrow or widen it
	}
	return err
}

// writeHostKey removes any host key the base shipped (a shared key would be one key for every VM)
// and makes this VM's Ed25519 key, the only one sshd is told to load.
func writeHostKey(root *os.Root, o TreeOptions) error {
	if err := root.MkdirAll("etc/ssh/sshd_config.d", 0o755); err != nil {
		return err
	}
	dir, err := root.Open("etc/ssh")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "ssh_host_") {
			if err := root.Remove("etc/ssh/" + e.Name()); err != nil {
				return err
			}
		}
	}
	private, public, _, err := openSSHEd25519(o.Random, "cathedral-vm")
	if err != nil {
		return errShortKey
	}
	if err := writeNew(root, "etc/ssh/ssh_host_ed25519_key", private, 0o600); err != nil {
		return err
	}
	if err := writeNew(root, "etc/ssh/ssh_host_ed25519_key.pub", public, 0o644); err != nil {
		return err
	}
	// Key login only, and the one host key cathedral-attest hashes. Everything else in sshd_config
	// is the customer's to change: they are root.
	return writeNew(root, "etc/ssh/sshd_config.d/10-cathedral-vm.conf",
		[]byte("HostKey /etc/ssh/ssh_host_ed25519_key\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"), 0o644)
}

// AssertCloudInitOff makes /etc/cloud/cloud-init.disabled exist as an empty regular file. The first
// boot calls it and so does every later boot (7.2 step 5), so the customer cannot leave cloud-init
// on across a restart by deleting the marker. A datasource from SMBIOS or a seed disk then does nothing.
func AssertCloudInitOff(root *os.Root) error {
	if err := root.MkdirAll("etc/cloud", 0o755); err != nil {
		return err
	}
	const marker = "etc/cloud/cloud-init.disabled"
	if info, err := root.Lstat(marker); err == nil {
		if info.Mode().IsRegular() && info.Size() == 0 {
			return nil
		}
		// A link or a non-empty file: replace it with the plain marker.
		if err := root.Remove(marker); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return writeNew(root, marker, nil, 0o644)
}

// WriteRecovery is step 4.3: make R and write the record to /var/lib/cathedral-vm/recovery.key
// (root only), flushed. The caller adds R as a keyslot afterwards (4.4); until that keyslot and the
// ready meta exist, a rerun makes a new R.
func WriteRecovery(root *os.Root, o TreeOptions) (vmrecovery.Record, error) {
	rec, err := vmrecovery.Generate(o.Random, o.Identity.VMID, o.Identity.IdentitySHA256)
	if err != nil {
		return vmrecovery.Record{}, err
	}
	raw, err := rec.Encode()
	if err != nil {
		return vmrecovery.Record{}, err
	}
	if err := root.MkdirAll("var/lib/cathedral-vm", 0o700); err != nil {
		return vmrecovery.Record{}, err
	}
	if err := root.Chmod("var/lib/cathedral-vm", 0o700); err != nil {
		return vmrecovery.Record{}, err
	}
	if err := writeNew(root, "var/lib/cathedral-vm/recovery.key", raw, 0o600); err != nil {
		return vmrecovery.Record{}, err
	}
	return rec, o.cut(CutRecovery)
}

// WriteNetwork writes the runtime network file under /run of the new root, never /etc.
func WriteNetwork(run *os.Root, linkRaw []byte) error {
	link, err := ParseLink(linkRaw)
	if err != nil {
		return err
	}
	if err := run.MkdirAll("systemd/network", 0o755); err != nil {
		return err
	}
	if err := run.Remove("systemd/network/10-uplink.network"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return writeNew(run, "systemd/network/10-uplink.network", link.NetworkFile(), 0o644)
}
