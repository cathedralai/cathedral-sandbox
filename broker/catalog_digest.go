// Catalog digest (AB#546). On 4 Nov a broker built from a commit older than the
// #388 pins was swapped in and direct template creates got the old LFM images.
// A swap now compares the new binary's digest (thin-broker -print-catalog-digest)
// with broker/catalog.digest on main and refuses a mismatch.
//
// The digest covers every field of a template that decides what a create gets:
// one line per template in listing order,
//
//	name \t image \t live \t sealed \t sealed_only \t cpu \t memory_gib \t disk_gib \n
//
// with booleans as true/false and integers in decimal. Each field is also in
// GET /v1/sandboxes/catalog (sealed_only absent means false), so a live readback
// can recompute it from the catalog response
// (scripts/broker_catalog_pin_check.sh readback). It hashes the table, not the
// create logic in templateCreateErr and applyCatalogTemplate.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

func catalogDigestLine(name, image string, live bool, sealed string, sealedOnly bool, cpu, memGiB, diskGiB int) string {
	return fmt.Sprintf("%s\t%s\t%t\t%s\t%t\t%d\t%d\t%d\n", name, image, live, sealed, sealedOnly, cpu, memGiB, diskGiB)
}

func catalogDigestOf(templates []catalogTemplate) string {
	var b strings.Builder
	for _, t := range templates {
		b.WriteString(catalogDigestLine(t.Name, t.Image, t.Live, string(t.Sealed), t.SealedOnly, t.CPU, t.MemoryGiB, t.DiskGiB))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// catalogDigest is the digest of the catalog compiled into this binary.
func catalogDigest() string { return catalogDigestOf(catalogTemplates) }

// printCatalogDigest is -print-catalog-digest: one line, nothing else, so a
// swap script can compare it byte for byte.
func printCatalogDigest(w io.Writer) error {
	_, err := fmt.Fprintln(w, catalogDigest())
	return err
}
