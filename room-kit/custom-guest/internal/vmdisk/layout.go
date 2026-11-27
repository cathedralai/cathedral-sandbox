// Package vmdisk is the sealed VM root disk logic of the VM init (spec r3
// 7.1, 7.2 steps 3 to 5): the LUKS device and intent area of root.raw, the
// VM header rules, the meta copies inside the encrypted volume, the
// classification into new, resume, open, locked, tampered and broken, the
// format steps F1 to F5 and the first-boot slot work.
//
// Pure logic (layout, records, header rules, classifier) builds on every
// platform; the device work is in the _linux_amd64 files. The cut hook used
// by test T5 exists only under the vmcuttest build tag.
package vmdisk

import "errors"

const (
	MiB = 1 << 20

	// IntentAreaBytes is the last MiB of root.raw, outside the LUKS device
	// (spec r3 7.1). Zero except while a first-boot format is in progress.
	IntentAreaBytes = 1 * MiB
	// RecordBytes is the size of the intent record and of each meta copy.
	RecordBytes = 4096

	// LUKSDataOffset is where the encrypted volume starts in the LUKS
	// device: the LUKS2 header and keyslot area before it. F3 formats with
	// exactly this offset and the header rules require it.
	LUKSDataOffset = 16 * MiB
	// MetaAreaBytes is the start of the encrypted volume; the file system
	// area follows it (spec r3 7.1).
	MetaAreaBytes = 16 * MiB
	// metaCopy1 is the offset of the second meta copy in the volume.
	metaCopy1 = 8 * MiB

	// MinDiskBytes leaves the header, the meta area, a file system area
	// and the intent area. MaxDiskBytes is the broker's 2048 GiB.
	MinDiskBytes = 64 * MiB
	MaxDiskBytes = 2048 << 30

	sectorBytes = 512
)

// Layout is the split of one root.raw (spec r3 7.1).
type Layout struct {
	DiskBytes    int64 // all of root.raw
	LUKSBytes    int64 // the LUKS device: offset 0, all but the intent area
	IntentOffset int64 // the intent area: the last MiB
}

// NewLayout refuses a size the init will not use: not a whole number of
// MiB, too small for header, meta and file system, or over the broker's cap.
func NewLayout(diskBytes int64) (Layout, error) {
	if diskBytes < MinDiskBytes || diskBytes > MaxDiskBytes || diskBytes%MiB != 0 {
		return Layout{}, errors.New("root disk size invalid")
	}
	return Layout{DiskBytes: diskBytes, LUKSBytes: diskBytes - IntentAreaBytes, IntentOffset: diskBytes - IntentAreaBytes}, nil
}

// LUKSSectors is the LUKS device length in 512-byte sectors (dm tables).
func (l Layout) LUKSSectors() uint64 { return uint64(l.LUKSBytes / sectorBytes) }

// VolumeBytes is the size of the encrypted volume (the crypt mapping).
func (l Layout) VolumeBytes() int64 { return l.LUKSBytes - LUKSDataOffset }

// FSBytes is the size of the file system area, after the meta area.
func (l Layout) FSBytes() int64 { return l.VolumeBytes() - MetaAreaBytes }

// MetaOffsets are the two meta copies' offsets in the volume.
func MetaOffsets() [2]int64 { return [2]int64{0, metaCopy1} }
