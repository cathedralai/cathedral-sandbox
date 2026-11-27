package vmdisk

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
)

// The VM header rules (spec r3 7.2): sealed-data.sh:84-104 without the
// slot-0 test at :100. One crypt segment with the data volume cipher and
// sector size; at least one keyslot; every keyslot 512-bit with no null
// cipher. Slot numbers mean nothing: the meta table names each slot's role.
//
// The rules here are stricter than the shell's in the ways the VM format
// pins (F3 formats with exactly these values): the segment offset is the
// 16 MiB F3 passes, its size is dynamic (the dm-linear LUKS device bounds
// it), it has no integrity, and every keyslot area is aes-xts-plain64 with a
// 512-bit key, which refuses a null keyslot cipher on any cryptsetup.

const (
	cipher     = "aes-xts-plain64"
	sectorSize = 4096
	keyBytes   = 64 // 512-bit XTS key
)

// Header is what a LUKS2 metadata dump says, read strictly.
type Header struct {
	Parsed   bool  // the JSON passed the strict reader
	Keyslots []int // sorted keyslot numbers; nil when !Parsed
	RulesOK  bool  // the VM header rules hold
}

// readJSON is internal/datavolume/header.go readJSON (copied, not imported:
// the guest builders share only bootstate and snp until the consolidation
// PR). It refuses duplicate keys and nesting past 16 before any field is used.
func readJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, errors.New("metadata nesting limit")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, errors.New("invalid metadata key")
			}
			if _, exists := m[name]; exists {
				return nil, errors.New("duplicate metadata key")
			}
			m[name], err = readJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
		}
		if t, err := d.Token(); err != nil || t != json.Delim('}') {
			return nil, errors.New("invalid metadata object")
		}
		return m, nil
	case json.Delim('['):
		var a []any
		for d.More() {
			v, err := readJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		if t, err := d.Token(); err != nil || t != json.Delim(']') {
			return nil, errors.New("invalid metadata array")
		}
		return a, nil
	default:
		return t, nil
	}
}

func object(v any) map[string]any { m, _ := v.(map[string]any); return m }

func number(v any, want int64) bool {
	n, ok := v.(json.Number)
	return ok && string(n) == strconv.FormatInt(want, 10)
}

func emptyArray(v any) bool {
	a, ok := v.([]any)
	return ok && len(a) == 0
}

func slotNumber(id string) (int, bool) {
	n, err := strconv.Atoi(id)
	return n, err == nil && n >= 0 && n <= 31 && strconv.Itoa(n) == id
}

// ParseHeader reads `cryptsetup luksDump --dump-json-metadata` output. A dump
// the strict reader refuses is Parsed false: its keyslots are unknown, and it
// never passes the rules.
func ParseHeader(raw []byte) Header {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return Header{}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readJSON(d, 0)
	if err != nil {
		return Header{}
	}
	if _, err := d.Token(); err != io.EOF {
		return Header{}
	}
	header := object(v)
	slots := object(header["keyslots"])
	if header == nil || len(slots) > 32 {
		return Header{}
	}
	h := Header{Parsed: true, Keyslots: []int{}}
	for id := range slots {
		n, ok := slotNumber(id)
		if !ok {
			return Header{}
		}
		h.Keyslots = append(h.Keyslots, n)
	}
	sort.Ints(h.Keyslots)
	h.RulesOK = rules(header)
	return h
}

func rules(header map[string]any) bool {
	segments := object(header["segments"])
	if len(segments) != 1 {
		return false
	}
	s := object(segments["0"])
	if s == nil || s["type"] != "crypt" || s["encryption"] != cipher || !number(s["sector_size"], sectorSize) ||
		s["iv_tweak"] != "0" || s["offset"] != strconv.Itoa(LUKSDataOffset) || s["size"] != "dynamic" {
		return false
	}
	if _, present := s["integrity"]; present {
		return false
	}
	if flags, present := s["flags"]; present && !emptyArray(flags) {
		return false
	}
	slots := object(header["keyslots"])
	if len(slots) == 0 {
		return false
	}
	for _, value := range slots {
		slot := object(value)
		area := object(slot["area"])
		if slot["type"] != "luks2" || !number(slot["key_size"], keyBytes) || area["type"] != "raw" ||
			area["encryption"] != cipher || !number(area["key_size"], keyBytes) {
			return false
		}
	}
	config := object(header["config"])
	if config == nil {
		return false
	}
	if flags, present := config["flags"]; present && !emptyArray(flags) {
		return false
	}
	if requirements, present := config["requirements"]; present {
		r := object(requirements)
		if len(r) != 1 || !emptyArray(r["mandatory"]) {
			return false
		}
	}
	return true
}

// cryptOptions are the dm-crypt optional parameters an opened VM volume may
// show. integrity: and anything unknown are refused.
var cryptOptions = map[string]bool{
	"sector_size:4096": true, "iv_large_sectors": true, "allow_discards": true, "same_cpu_crypt": true,
	"submit_from_crypt_cpus": true, "no_read_workqueue": true, "no_write_workqueue": true,
}

// CheckCryptTable checks the active table of the opened volume, the second
// read sealed-data.sh's verify_header makes (dmsetup table there, the DM
// ioctl here): one crypt target over exactly the LUKS device from the 16 MiB
// offset, the data volume cipher, 4 KiB sectors. Field 1 of params is the
// key (hex, or a keyring reference): it is never turned into a string, and
// the caller clears params.
func CheckCryptTable(targetType string, start, length uint64, params []byte, luksDev string, luksSectors uint64) error {
	bad := errors.New("the opened volume is not the VM layout")
	f := bytes.Fields(params)
	if targetType != "crypt" || start != 0 || length != luksSectors-LUKSDataOffset/sectorBytes || len(f) < 6 {
		return bad
	}
	if string(f[0]) != cipher || string(f[2]) != "0" || string(f[3]) != luksDev ||
		string(f[4]) != strconv.Itoa(LUKSDataOffset/sectorBytes) {
		return bad
	}
	n, err := strconv.Atoi(string(f[5]))
	if err != nil || n != len(f)-6 {
		return bad
	}
	sector := false
	for _, opt := range f[6:] {
		if !cryptOptions[string(opt)] {
			return bad
		}
		sector = sector || string(opt) == "sector_size:4096"
	}
	if !sector {
		return bad
	}
	return nil
}

// MinCryptsetup is sealed-data.sh's floor (MIN_CRYPTSETUP, :51): 2.8.1
// refuses null ciphers on keyslots.
const MinCryptsetup = "2.8.1"

// CheckCryptsetupVersion reads `cryptsetup --version` ("cryptsetup 2.8.4
// flags: ...") and refuses anything below MinCryptsetup or unparseable.
func CheckCryptsetupVersion(out string) error {
	bad := errors.New("cryptsetup is older than " + MinCryptsetup + " or unreadable")
	fields := strings.Fields(out)
	if len(fields) < 2 || fields[0] != "cryptsetup" {
		return bad
	}
	parse := func(s string) ([3]int, bool) {
		var v [3]int
		parts := strings.Split(strings.SplitN(s, "-", 2)[0], ".")
		if len(parts) < 2 || len(parts) > 3 {
			return v, false
		}
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || strconv.Itoa(n) != p {
				return v, false
			}
			v[i] = n
		}
		return v, true
	}
	have, ok := parse(fields[1])
	want, _ := parse(MinCryptsetup)
	if !ok {
		return bad
	}
	for i := range have {
		if have[i] != want[i] {
			if have[i] < want[i] {
				return bad
			}
			return nil
		}
	}
	return nil
}
