package vmkey

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const device = "/dev/sev-guest"

// getDerivedKey is _IOWR('S', 0x1, struct snp_guest_request_ioctl), as
// sealed_data_key.SNP_GET_DERIVED_KEY.
const getDerivedKey = uintptr(3<<30 | 32<<16 | 'S'<<8 | 0x1)

// guestRequest follows the Linux snp_guest_request_ioctl ABI on amd64
// (the same layout as internal/snp).
type guestRequest struct {
	Version  uint8
	_        [7]byte
	Request  uint64
	Response uint64
	ExitInfo uint64
}

// derivedKeyRequest is struct snp_derived_key_req (MSG_KEY_REQ).
type derivedKeyRequest struct {
	RootKeySelect    uint32
	Reserved         uint32
	GuestFieldSelect uint64
	VMPL             uint32
	GuestSVN         uint32
	TCBVersion       uint64
}

// Material is the key and its public label for one boot. Clear() it once
// cryptsetup has the passphrase.
type Material struct {
	Passphrase [32]byte
	KeyID      string
}

func (m *Material) Clear() { clear(m.Passphrase[:]) }

// Derive asks the chip for this guest's key and mixes in HOST_DATA, which
// the caller took from a report it already checked against the identity.
// Call only as root in the measured init after /dev/sev-guest is root-only.
func Derive(hostData [32]byte) (Material, error) {
	if os.Geteuid() != 0 {
		return Material{}, errors.New("root required")
	}
	return deriveWith(hostData, nativeCall)
}

// deriveWith is a unit-test seam only; no input selects another backend.
func deriveWith(hostData [32]byte, call func(*derivedKeyRequest, *[64]byte) (uint64, error)) (Material, error) {
	request := &derivedKeyRequest{RootKeySelect: RootKeyVCEK, GuestFieldSelect: FieldSelect, VMPL: VMPL}
	response := new([64]byte)
	defer clear(response[:])
	exit, err := call(request, response)
	if err != nil {
		return Material{}, fmt.Errorf("SNP_GET_DERIVED_KEY failed: %w; firmware error %#x, VMM error %#x",
			err, exit&0xffffffff, exit>>32)
	}
	if exit != 0 {
		return Material{}, errors.New("SNP firmware or VMM error")
	}
	if status := binary.LittleEndian.Uint32(response[:4]); status != 0 {
		return Material{}, fmt.Errorf("MSG_KEY_RSP status %#x", status)
	}
	var chip [32]byte
	copy(chip[:], response[32:64])
	defer clear(chip[:])
	if chip == [32]byte{} {
		return Material{}, errors.New("MSG_KEY_RSP gave an all-zero key")
	}
	return Material{Passphrase: Passphrase(chip, FieldSelect, hostData), KeyID: KeyID(chip, FieldSelect, hostData)}, nil
}

func nativeCall(request *derivedKeyRequest, response *[64]byte) (uint64, error) {
	if unsafe.Sizeof(guestRequest{}) != 32 || unsafe.Sizeof(derivedKeyRequest{}) != 32 {
		return 0, errors.New("unsupported SNP ABI")
	}
	fd, err := syscall.Open(device, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	var meta syscall.Stat_t
	if err = syscall.Fstat(fd, &meta); err != nil {
		return 0, err
	}
	if meta.Mode&syscall.S_IFMT != syscall.S_IFCHR || meta.Uid != 0 || meta.Mode&0077 != 0 {
		return 0, errors.New("SNP device must be a root-only character device")
	}
	command := new(guestRequest)
	var pin runtime.Pinner
	pin.Pin(request)
	pin.Pin(response)
	pin.Pin(command)
	defer pin.Unpin()
	command.Version = 1
	command.Request = uint64(uintptr(unsafe.Pointer(request)))
	command.Response = uint64(uintptr(unsafe.Pointer(response)))
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), getDerivedKey, uintptr(unsafe.Pointer(command)))
	runtime.KeepAlive(request)
	runtime.KeepAlive(response)
	runtime.KeepAlive(command)
	if errno != 0 {
		return command.ExitInfo, errno
	}
	return command.ExitInfo, nil
}
