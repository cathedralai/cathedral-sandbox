// Flag-gated admission against Cathedral's signed sealed-hotels list (URnetwork Q3).
//
// When config "signed_measurements_url" is set and "signed_measurements_admission"
// is true, a hotel's launch measurement must appear in the signed list for its
// hotel id (or, if the id is absent, in any hotel entry's approved measurements).
// The list Ed25519 signature is verified against pinned keys (default:
// sealed-hotels-local-1) before membership is trusted. On fetch or verify
// failure the broker falls back to the local sealed_measurements pin list so
// admission does not flap.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const signedMeasurementsSchema = "cathedral_sealed_hotels_v1"

// Default pin for sealed-hotels-local-1 (same as room-kit/verify_sealed_hotels.py).
var defaultSignedMeasurementPins = map[string]signedMeasurementPin{
	"sealed-hotels-local-1": {
		PublicKeyHex: "fce2eb94433c0d0766be0c9c186de252e7fa99d6956ff1850f3159af6002e358",
		NotBefore:    "2026-11-17T15:59:33Z",
		NotAfter:     "2027-02-15T00:00:00Z",
	},
}

type signedMeasurementPin struct {
	PublicKeyHex string `json:"public_key_hex"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
}

type signedHotelsRelease struct {
	Schema      string `json:"schema"`
	Release     int64  `json:"release"`
	GeneratedAt string `json:"generated_at"`
	ValidFrom   string `json:"valid_from"`
	ValidUntil  string `json:"valid_until"`
	KeyID       string `json:"key_id"`
	Hotels      map[string]struct {
		Measurements []string `json:"measurements"`
		ChipID       string   `json:"chip_id"`
	} `json:"hotels"`
	Signature *struct {
		Algorithm   string `json:"algorithm"`
		ValueBase64 string `json:"value_base64"`
	} `json:"signature"`
}

type signedMeasurementsCache struct {
	mu       sync.Mutex
	byHotel  map[string][]string
	byChip   map[string][]string // chip_id -> hotel ids that list it
	all      []string
	loadedAt time.Time
	source   string
}

var signedMeas = &signedMeasurementsCache{}

// canonicalJSONASCII matches room-kit/verify_sealed_hotels.py:
// json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).
func canonicalJSONASCII(v any) ([]byte, error) {
	return marshalCanonical(v)
}

func marshalCanonical(v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if x {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case float64:
		// JSON numbers from encoding/json Unmarshal are float64; refuse non-integers
		// for release fields by formatting without decimal when whole.
		if x == float64(int64(x)) {
			return []byte(fmt.Sprintf("%d", int64(x))), nil
		}
		b, err := json.Marshal(x)
		return b, err
	case json.Number:
		return []byte(x.String()), nil
	case string:
		b, err := json.Marshal(x)
		return b, err
	case []any:
		parts := make([][]byte, len(x))
		for i, el := range x {
			b, err := marshalCanonical(el)
			if err != nil {
				return nil, err
			}
			parts[i] = b
		}
		out := []byte{'['}
		for i, p := range parts {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, p...)
		}
		out = append(out, ']')
		return out, nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			vb, err := marshalCanonical(x[k])
			if err != nil {
				return nil, err
			}
			out = append(out, kb...)
			out = append(out, ':')
			out = append(out, vb...)
		}
		out = append(out, '}')
		return out, nil
	default:
		// Fallback: re-encode through json then re-parse as map/list.
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		var anyVal any
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if err := dec.Decode(&anyVal); err != nil {
			return nil, err
		}
		return marshalCanonical(anyVal)
	}
}

func parsePinTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

func pinsFor(cfg *config) map[string]signedMeasurementPin {
	if cfg != nil && len(cfg.SignedMeasurementsPins) > 0 {
		return cfg.SignedMeasurementsPins
	}
	return defaultSignedMeasurementPins
}

func verifySignedMeasurements(raw []byte, pins map[string]signedMeasurementPin, now time.Time) error {
	var top map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return fmt.Errorf("signed measurements json: %w", err)
	}
	sigObj, _ := top["signature"].(map[string]any)
	if sigObj == nil {
		return fmt.Errorf("signed measurements missing signature")
	}
	alg, _ := sigObj["algorithm"].(string)
	if alg != "ed25519" {
		return fmt.Errorf("signed measurements algorithm %q, want ed25519", alg)
	}
	sigB64, _ := sigObj["value_base64"].(string)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signed measurements signature must be 64-byte base64")
	}
	keyID, _ := top["key_id"].(string)
	pin, ok := pins[keyID]
	if !ok {
		return fmt.Errorf("signed measurements key_id %q not pinned", keyID)
	}
	pub, err := hex.DecodeString(pin.PublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("signed measurements pin %q public key invalid", keyID)
	}
	unsigned := map[string]any{}
	for k, v := range top {
		if k == "signature" {
			continue
		}
		unsigned[k] = v
	}
	msg, err := marshalCanonical(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return fmt.Errorf("signed measurements signature verification failed")
	}
	schema, _ := top["schema"].(string)
	if schema != "" && schema != signedMeasurementsSchema {
		return fmt.Errorf("signed measurements schema %q, want %s", schema, signedMeasurementsSchema)
	}
	generatedAt, _ := top["generated_at"].(string)
	if generatedAt != "" && pin.NotBefore != "" && pin.NotAfter != "" {
		gen, err := parsePinTime(generatedAt)
		if err != nil {
			return fmt.Errorf("signed measurements generated_at: %w", err)
		}
		nb, err1 := parsePinTime(pin.NotBefore)
		na, err2 := parsePinTime(pin.NotAfter)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("signed measurements pin window invalid")
		}
		if gen.Before(nb) || gen.After(na) {
			return fmt.Errorf("signed measurements key %q pin window does not contain generated_at", keyID)
		}
		if now.Before(nb) || now.After(na) {
			return fmt.Errorf("signed measurements key %q pin window does not contain now", keyID)
		}
	}
	return nil
}

func (c *signedMeasurementsCache) load(raw []byte, source string) error {
	var doc signedHotelsRelease
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if doc.Schema != "" && doc.Schema != signedMeasurementsSchema {
		return fmt.Errorf("signed measurements schema %q, want %s", doc.Schema, signedMeasurementsSchema)
	}
	byHotel := map[string][]string{}
	byChip := map[string][]string{}
	all := []string{}
	seen := map[string]bool{}
	for id, hotel := range doc.Hotels {
		ms := make([]string, 0, len(hotel.Measurements))
		for _, m := range hotel.Measurements {
			m = strings.ToLower(strings.TrimSpace(m))
			if len(m) != 96 {
				continue
			}
			ms = append(ms, m)
			if !seen[m] {
				seen[m] = true
				all = append(all, m)
			}
		}
		if len(ms) > 0 {
			byHotel[id] = ms
		}
		chip := strings.ToLower(strings.TrimSpace(hotel.ChipID))
		if len(chip) == 128 {
			byChip[chip] = append(byChip[chip], id)
		}
	}
	if len(all) == 0 {
		return fmt.Errorf("signed measurements list has no 96-hex measurements")
	}
	c.mu.Lock()
	c.byHotel, c.byChip, c.all, c.loadedAt, c.source = byHotel, byChip, all, time.Now().UTC(), source
	c.mu.Unlock()
	return nil
}

func (c *signedMeasurementsCache) allow(hotelID, measurement string) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.all) == 0 {
		return false, "signed measurements not loaded"
	}
	m := strings.ToLower(measurement)
	if ms, ok := c.byHotel[hotelID]; ok {
		for _, x := range ms {
			if x == m {
				return true, c.source
			}
		}
		return false, "measurement not in signed list for hotel " + hotelID
	}
	for _, x := range c.all {
		if x == m {
			return true, c.source
		}
	}
	return false, "measurement not in signed list"
}

func (c *signedMeasurementsCache) hotelsForChip(chipID string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.byChip[strings.ToLower(chipID)]...)
}

func fetchSignedMeasurements(url string) ([]byte, error) {
	if strings.HasPrefix(url, "file:") {
		return os.ReadFile(strings.TrimPrefix(url, "file:"))
	}
	if strings.HasPrefix(url, "/") || strings.HasPrefix(url, "./") {
		return os.ReadFile(url)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s answered %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// refreshSignedMeasurements loads and verifies the signed list when configured.
func (b *broker) refreshSignedMeasurements() {
	url := strings.TrimSpace(b.cfg.SignedMeasurementsURL)
	if url == "" || !b.cfg.SignedMeasurementsAdmission {
		return
	}
	raw, err := fetchSignedMeasurements(url)
	if err != nil {
		log.Printf("signed measurements: fetch failed (%v); keeping prior cache / local pin fallback", err)
		return
	}
	if err := verifySignedMeasurements(raw, pinsFor(&b.cfg), time.Now().UTC()); err != nil {
		log.Printf("signed measurements: verify failed (%v); keeping prior cache / local pin fallback", err)
		return
	}
	if err := signedMeas.load(raw, url); err != nil {
		log.Printf("signed measurements: load failed (%v); keeping prior cache / local pin fallback", err)
		return
	}
	log.Printf("signed measurements: verified and loaded %d hotels from %s", len(signedMeas.byHotel), url)
}

// measurementAllowed reports whether measurement may admit hotelID. When the
// signed-admission flag is off, only the local pin list applies (caller). When
// on and the signed list is loaded, the measurement must be in that list; if
// the signed list is empty (never loaded), localPins are used as fallback.
func measurementAllowed(hotelID, measurement string, localPins []string, signedRequired bool) (bool, string) {
	if !signedRequired {
		if len(localPins) == 0 || inFold(localPins, measurement) {
			return true, "local"
		}
		return false, "measurement not in sealed_measurements"
	}
	ok, src := signedMeas.allow(hotelID, measurement)
	if ok {
		return true, src
	}
	// Fallback: never-loaded or stale list → local pin, so admission does not flap.
	signedMeas.mu.Lock()
	empty := len(signedMeas.all) == 0
	signedMeas.mu.Unlock()
	if empty && len(localPins) > 0 && inFold(localPins, measurement) {
		return true, "local_fallback"
	}
	if empty {
		return false, "signed measurements not loaded and no local pin match"
	}
	return false, src
}
