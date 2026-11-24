// Flag-gated admission against Cathedral's signed sealed-hotels list (URnetwork Q3).
//
// When config "signed_measurements_url" is set and "signed_measurements_admission"
// is true, a hotel's launch measurement must appear in the signed list for its
// hotel id (or, if the id is absent, in any hotel entry's approved measurements).
// On fetch failure the broker falls back to the local sealed_measurements pin
// list so admission does not flap. Signature verification of the list is done
// by operators/clients offline; this gate checks membership of the published
// measurement set.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const signedMeasurementsSchema = "cathedral_sealed_hotels_v1"

type signedHotelsRelease struct {
	Schema string `json:"schema"`
	Hotels map[string]struct {
		Measurements []string `json:"measurements"`
		ChipID       string   `json:"chip_id"`
	} `json:"hotels"`
}

type signedMeasurementsCache struct {
	mu       sync.Mutex
	byHotel  map[string][]string
	all      []string
	loadedAt time.Time
	source   string
}

var signedMeas = &signedMeasurementsCache{}

func (c *signedMeasurementsCache) load(raw []byte, source string) error {
	var doc signedHotelsRelease
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if doc.Schema != "" && doc.Schema != signedMeasurementsSchema {
		return fmt.Errorf("signed measurements schema %q, want %s", doc.Schema, signedMeasurementsSchema)
	}
	byHotel := map[string][]string{}
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
	}
	if len(all) == 0 {
		return fmt.Errorf("signed measurements list has no 96-hex measurements")
	}
	c.mu.Lock()
	c.byHotel, c.all, c.loadedAt, c.source = byHotel, all, time.Now().UTC(), source
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

// refreshSignedMeasurements loads the signed list when configured. Safe to call
// from admission; failures leave the previous cache (or empty) in place.
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
	if err := signedMeas.load(raw, url); err != nil {
		log.Printf("signed measurements: load failed (%v); keeping prior cache / local pin fallback", err)
		return
	}
	log.Printf("signed measurements: loaded %d hotels from %s", len(signedMeas.byHotel), url)
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
