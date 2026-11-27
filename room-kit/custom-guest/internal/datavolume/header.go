package datavolume

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

// readJSON rejects duplicate keys before selecting security fields. It is
// bounded independently of cryptsetup's output so hostile metadata cannot
// introduce alternate interpretations or unbounded nesting.
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

// CheckHeaderPolicy checks only the intended encryption/integrity layout in
// cryptsetup luksDump --dump-json-metadata output. It does not verify a LUKS
// checksum, passphrase, disk identity or the active device-mapper table. The
// unlock caller must independently validate those before any filesystem write.
// Never interpret nil as permission to format or mount an existing volume.
func CheckHeaderPolicy(raw []byte) error {
	fail := errors.New("data volume encryption policy mismatch")
	if len(raw) == 0 || len(raw) > 1<<20 {
		return fail
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readJSON(d, 0)
	if err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fail
	}
	header := object(v)
	segments := object(header["segments"])
	if len(segments) != 1 {
		return fail
	}
	s := object(segments["0"])
	if s["type"] != "crypt" || s["encryption"] != "aes-xts-plain64" ||
		!number(s["sector_size"], 4096) || s["iv_tweak"] != "0" {
		return fail
	}
	if flags, present := s["flags"]; present && !emptyArray(flags) {
		return fail
	}
	integrity := object(s["integrity"])
	if integrity["type"] != "hmac(sha256)" || integrity["journal_encryption"] != "none" ||
		integrity["journal_integrity"] != "none" {
		return fail
	}
	// cryptsetup 2.8.4 defaults hmac(sha256) to 32 bytes and emits key_size
	// only for an explicitly supplied integrity-key-size.
	if n, present := integrity["key_size"]; present && !number(n, 32) {
		return fail
	}
	slots := object(header["keyslots"])
	if len(slots) == 0 || len(slots) > 32 {
		return fail
	}
	for id, value := range slots {
		n, err := strconv.Atoi(id)
		if err != nil || n < 0 || n > 31 || strconv.Itoa(n) != id {
			return fail
		}
		slot := object(value)
		area := object(slot["area"])
		// 64-byte XTS key plus 32-byte HMAC key. All slots must encrypt their
		// key material too; a successful passphrase alone does not prove this.
		if slot["type"] != "luks2" || !number(slot["key_size"], 96) ||
			area["type"] != "raw" || area["encryption"] != "aes-xts-plain64" || !number(area["key_size"], 64) {
			return fail
		}
	}
	config := object(header["config"])
	if config == nil {
		return fail
	}
	if flags, present := config["flags"]; present && !emptyArray(flags) {
		return fail
	}
	if requirements, present := config["requirements"]; present {
		r := object(requirements)
		if len(r) != 1 || !emptyArray(r["mandatory"]) {
			return fail
		}
	}
	return nil
}
