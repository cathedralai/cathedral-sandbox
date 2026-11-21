// Claim journal (AB#894, phase 2 PR 1, work order revision 6): the
// append-only record the broker will write before a ready-room create's
// answer leaves, so that a crash never leaves a customer holding a room whose
// claim the broker cannot prove. Nothing calls it yet: PR 5 of the phase 2
// work order writes the records (won, outcome, revoked, cancel, abandoned,
// granted, removed; the caller's kinds, opaque here), PR 2 reads completeness
// before its pool manager may act, and the usage receipts lane sets the peer
// head.
//
// Files, all under state_dir:
//
//	claims.id                       the journal's random id, written last at creation
//	claims/CURRENT                  names the live generation, "gen-N"
//	claims/gen-N/journal-id         the same id
//	claims/gen-N/manifest.json      the generation's segments
//	claims/gen-N/ack-head-a, -b     the two head files
//	claims/gen-N/<first seq, 20 digits>.jsonl   segments, mode 0600
//
// One JSON line per record, schema cathedral_claim_record_v1:
//
//	{"schema", "seq", "prev", "kind", "body"}
//
// seq rises with every line and never goes back, across generations and
// restarts (a failed batch burns its seqs). prev is the sha256 of the line
// before it in the generation (64 zeros for the first), so a generation's
// lines form one chain. kind names the record; body is the caller's JSON,
// opaque here. Kinds that start with journal_ are the journal's own and never
// reach a caller. append takes one record, one line: a record that carries two
// facts (a revoked with a request's new outcome) survives whole or not at all.
//
// # Caller rules (read before wiring a caller)
//
//   - An error from append is indeterminate: the record may be durable and
//     may come back at replay. For example, when the head file's fsync fails
//     after the batch's write and the head file's write both landed, append
//     reports the error, and if the process stops before a later batch
//     withdraws those seqs, the next open replays the record and its head
//     covers it. So a caller never frees or re-grants anything on an append
//     error, keys every record by its claim or request id, and settles the
//     outcome from what replay yields.
//   - compact can return an error after it committed the new generation
//     (CURRENT renamed, its directory not yet synced): a compaction error is
//     indeterminate the same way.
//   - Build a snapshot only after every earlier append has been
//     acknowledged: compact replaces every record appended before it was
//     called, so one still in flight that the snapshot does not hold is gone.
//   - open holds an exclusive lock on claims/ until close (see "Lock"). A
//     second open fails with errClaimJournalLocked, which is not incomplete:
//     retry once the holder has closed. An incomplete journal comes back
//     holding the lock as well; close it to give the lock back.
//
// # Lock
//
// open takes an exclusive, non-blocking flock on claims/ before it reads,
// syncs, removes or writes anything there, and holds it until close; an open
// that fails gives it back. The invariant, enforced in one place (create and
// load start by checking the lock is held): nothing reads, writes, syncs or
// removes inside claims/ without the lock. open decides only from a look at
// claims.id and claims/ made after the lock is held, so an opener that looked
// while another one was initializing decides again from what is there now.
//
// A look reads claims.id first and then stats claims/. claims/ is made
// before claims.id is ever written, so a valid claims.id followed by a
// missing claims/ means claims/ was removed, not that another open is still
// making it. That one case, seen in one look, is the only open without the
// lock: there is nothing to lock and nothing a writer could be using, and
// open reports it as incomplete without making claims/. Every other open,
// the read-only open of an incomplete journal included, takes the lock:
// every open path reads files a live writer may be changing and could judge
// a journal in the middle of a write. On a first start claims/ is made first
// so that it can be locked, so two first opens cannot both initialize.
//
// A claims/ removed and made again between the look and the lock would leave
// the lock on a dead directory: after locking, open checks that the locked
// descriptor is the claims/ the path names, and looks again if not (three
// times at most, then it fails and can be retried). A claims/ replaced while
// the journal is open is not detected; that is a person removing a live
// journal.
//
// A second open while a holder lives, in this process or another, fails with
// errClaimJournalLocked, changes no file and can be retried once the holder
// closes. Limits: the lock is advisory (only opens of this journal honour
// it); it holds on one host only; a network filesystem may not honour flock;
// and a process that dies gives it back, which is what a restart needs. It
// uses flock, so the journal builds on Unix only.
//
// # Writing
//
// append queues a record under the journal's own mutex and returns a channel.
// One writer goroutine takes everything queued (at most 4 MB), writes it with
// one write and fsyncs the segment, then overwrites the head file holding the
// lower seq with the batch's last seq, its chain hash and the peer head, and
// fsyncs that file, and only then closes the channel of every record in the
// batch (group commit): two fsyncs per batch. A failed batch sends its error
// on every channel in it. The caller waits with its own deadline; the journal
// never gives up on a record by itself. No lock is held for disk I/O (the
// mutex guards only the queue and the peer head), so a hung disk stalls the
// callers waiting on it and nobody else.
//
// Durability elsewhere follows the usage log's rules (#622,
// broker/usage_meter.go): a batch counts only after its fsync returns; a new
// segment file is created and its directory synced, then the manifest
// (temporary file, fsync, rename, directory fsync) lists it, and only then
// does it take a record; a directory the journal makes (claims/ and each
// generation, and state_dir and its ancestors when missing) is synced into its
// parent, top down, before anything trusts it, and at initialization every
// ancestor of claims/ the journal can open is synced again, existing or not,
// because an earlier attempt may have made it and failed before its entry
// was durable; at replay a torn last line is
// skipped and logged, and the segment holding it never takes another record
// (each open starts a new segment).
//
// Recovery contract: a record is in the journal at replay if its bytes were
// written, synced or not (a process kill keeps the page cache); every
// acknowledged record is inside the valid head. The head proves consistency
// with the surviving head file, not completeness against a rollback that
// replaced the head and the tail together. Phase 2 does not detect that case.
//
// So a process killed after a batch's write, before its fsyncs returned, can
// leave whole records that replay although no caller was told they are
// durable; a power loss in the same place may drop them. Callers treat a
// replayed record past what they know was acknowledged as possibly
// unacknowledged. A record whose predecessor did not survive (a power loss
// can keep a later page of an unsynced batch and lose an earlier one) is off
// the chain and is skipped; a process kill leaves none.
//
// One refinement: a batch whose write or fsync failed has had its error
// delivered and its seqs are withdrawn. The next batch starts with a
// journal_void line naming them, and replay skips a withdrawn seq once that
// line is on disk, so a caller that appends a failed record again (under a
// new seq) replays it once.
//
// # Head files
//
// ack-head-a and ack-head-b each hold one fixed-size record: a seq, the chain
// hash of that seq's line, the peer head, and the record's own checksum. Each
// batch overwrites the file holding the lower seq (a file whose last write
// did not sync counts as lowest) and fsyncs it. A reader takes the valid file
// with the higher seq; a missing, short or spoiled file is not valid. Storage
// assumption: a write to one file never damages another file's data. Nothing
// relies on sector atomicity inside a file: a power loss while one head file
// is written can spoil that file only, and the other still holds the previous
// batch's head. Because each line's prev commits to the one before, a valid
// head whose line is on the chain proves every acknowledged record before it
// is present and unchanged, in closed and open segments alike. Limit: this
// covers a write that is interrupted; a head file that cannot be read at
// all (an I/O error, not a missing, short or spoiled file) is no verdict:
// open fails with that error and may be tried again, and never falls back
// on the other file, which may hold the older head and so accept a tail
// shorter than what was acknowledged. It does not detect a later corruption
// of an acknowledged head file, nor a rollback that replaces a head file and
// the tail together.
//
// The peer head is the usage log's durable head. Callers set it with
// setPeerHead; every head file write records the latest value, and open
// returns it with the journal's own acknowledged head. Nothing in phase 2
// depends on the peer head: no caller compares it; it stays as a passive
// field for later hardening. The journal makes no decision from it either.
//
// # Generations, creation, recovery (design 2.1)
//
// CURRENT is replaced only by temporary file, fsync, rename, directory fsync:
// that rename is the generation commit. Creation writes gen-1/ and its files
// (each fsynced, then the directory), then CURRENT, then claims.id last, the
// same atomic way; the journal accepts no record before claims.id is durable.
// A compaction writes gen-N+1/ whole the same way (the snapshot segment,
// manifest, both head files and journal-id), opens what the writer needs for
// it, commits CURRENT, and only then deletes gen-N/. Rule: once CURRENT names
// generation N+1, no record is ever acknowledged in generation N. The writer
// acquires everything first so adopting N+1 cannot fail; a rename that
// reports an error is checked by reading CURRENT back, and when that cannot
// be read the journal refuses every further write until a restart. The
// caller builds the snapshot (the complete live state, design 2.1); the
// journal only guarantees it is committed whole. The snapshot replaces every
// record appended before compact was called; every record appended after it
// goes into the new generation. No record is written while a compaction
// runs.
//
// open first syncs state_dir and claims/, so that the names claims.id and
// CURRENT it found are durable before it removes anything they make obsolete
// or acknowledges a record under them (a crash can leave either rename
// visible but not yet synced). It then removes, without reporting anything:
// a generation newer than CURRENT (unfinished) or older (obsolete), an empty
// unlisted segment, leftover temporary files (claims.id's among them), and
// an initialization that left no valid claims.id and holds no record (it is
// redone; a claims.id that does not parse counts as missing). open reports
// incomplete (errClaimJournalIncomplete) for real loss only: claims.id
// present but claims/ or CURRENT missing; CURRENT naming a missing
// generation; another journal-id; a missing or unreadable manifest; a listed
// segment missing, or a closed one shorter than its size or last seq, or
// with another sha256; the chain ending before the valid head, or another
// chain hash there; a non-empty unlisted segment; neither head file valid
// (both missing, short or spoiled; a file open cannot read at all is an I/O
// error, returned as such, not loss); records in a generation while
// claims.id is missing or does not parse. An incomplete
// journal is read only: replay yields what is readable, append and compact
// refuse, and open changes no file, so the evidence stays for a person.
//
// Not detected, by design: state_dir (or claims/) restored from an older copy
// that is consistent in itself, which every local check accepts (design 2.1,
// "Rollback"; phase 2 does not detect that case), and a disk that
// acknowledges fsync without keeping the data.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	claimRecordSchema    = "cathedral_claim_record_v1"
	claimManifestSchema  = "cathedral_claim_manifest_v1"
	claimJournalDirName  = "claims"
	claimJournalIDName   = "claims.id" // in state_dir
	claimCurrentName     = "CURRENT"
	claimJournalIDInGen  = "journal-id"
	claimManifestName    = "manifest.json"
	claimVoidKind        = "journal_void"
	claimSegmentMaxBytes = 8 << 20 // a segment closes past this
	claimWriteMaxBytes   = 4 << 20 // one batch write takes at most this
	claimRecordMaxBytes  = 1 << 20 // one record's body
	claimHeadFileBytes   = 256     // one head file: body, a space, 64 hex of the body's sha256
	claimHeadBodyBytes   = claimHeadFileBytes - 65
)

// claimHeadNames are the two head files of a generation.
var claimHeadNames = [2]string{"ack-head-a", "ack-head-b"}

var (
	errClaimJournalIncomplete = errors.New("claim journal incomplete")
	errClaimJournalClosed     = errors.New("claim journal closed")
	errClaimJournalLocked     = errors.New("claim journal locked by another open")
	errClaimJournalNotLocked  = errors.New("claim journal: internal error: claims/ reached without its lock")

	claimGenesis   = strings.Repeat("0", 64) // prev of a generation's first line
	claimSegmentRE = regexp.MustCompile(`^[0-9]{20}\.jsonl$`)
	claimGenRE     = regexp.MustCompile(`^gen-([1-9][0-9]{0,17})$`)
	claimKindRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	claimIDRE      = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// claimRecord is one journal record. append ignores Seq; replay sets it.
type claimRecord struct {
	Seq  int64
	Kind string
	Body json.RawMessage // the caller's JSON, opaque here; nil for none
}

// claimJournalIncompleteError lists why open could not prove the journal
// whole. It matches errClaimJournalIncomplete.
type claimJournalIncompleteError struct{ reasons []string }

func (e *claimJournalIncompleteError) Error() string {
	return "claim journal incomplete: " + strings.Join(e.reasons, "; ")
}

func (e *claimJournalIncompleteError) Is(target error) bool {
	return target == errClaimJournalIncomplete
}

// claimJournalDisk is every disk call that decides durability. Tests replace
// one to fail, hang, or stop where a crash would (step).
type claimJournalDisk struct {
	write    func(f *os.File, p []byte) error   // a batch into the open segment
	sync     func(f *os.File) error             // the open segment's fsync, once per batch
	cut      func(f *os.File, size int64) error // take a failed batch's bytes back
	syncHead func(f *os.File) error             // the written head file's fsync, once per batch
	syncFile func(f *os.File) error             // any other file: manifest, ids, CURRENT, a generation's files, a closing segment
	syncDir  func(dir string) error
	open     func(path string, flag int, perm os.FileMode) (*os.File, error) // a head file
	rename   func(oldpath, newpath string) error                             // a temporary file into place
	readBack func(path string) (string, error)                               // CURRENT read back after a rename that reported an error
	readHead func(path string) ([]byte, error)                               // a head file at open
	remove   func(path string) error                                         // an empty segment that was never listed
	onLock   func(f *os.File)                                                // nil: nothing; tests use it to drop a lock as a dying process would
	step     func(point string)                                              // nil: nothing; names a point a crash may hit
}

func (d claimJournalDisk) withDefaults() claimJournalDisk {
	if d.write == nil {
		d.write = func(f *os.File, p []byte) error { _, err := f.Write(p); return err }
	}
	if d.sync == nil {
		d.sync = (*os.File).Sync
	}
	if d.cut == nil {
		d.cut = (*os.File).Truncate
	}
	if d.syncHead == nil {
		d.syncHead = (*os.File).Sync
	}
	if d.syncFile == nil {
		d.syncFile = (*os.File).Sync
	}
	if d.syncDir == nil {
		d.syncDir = claimJournalSyncDir
	}
	if d.open == nil {
		d.open = os.OpenFile
	}
	if d.rename == nil {
		d.rename = os.Rename
	}
	if d.readBack == nil {
		d.readBack = readClaimText
	}
	if d.readHead == nil {
		d.readHead = os.ReadFile
	}
	if d.remove == nil {
		d.remove = os.Remove
	}
	if d.onLock == nil {
		d.onLock = func(*os.File) {}
	}
	if d.step == nil {
		d.step = func(string) {}
	}
	return d
}

func claimJournalSyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// claimJournalTiming is what one batch or compaction cost, on the writer:
// Queue from append to the writer taking the record (mean and max over the
// batch), Roll the start of a new segment (0 for most batches), Write the one
// write, Sync the segment fsync, Head the head file's write and fsync, Total a
// compaction.
type claimJournalTiming struct {
	Compaction              bool
	Records, Bytes          int
	Queue, QueueMax         time.Duration
	Roll, Write, Sync, Head time.Duration
	Total                   time.Duration
	Err                     error
}

type claimJournalOptions struct {
	disk       claimJournalDisk
	segmentMax int64                    // 0: claimSegmentMaxBytes; tests lower it
	observe    func(claimJournalTiming) // nil in production; tests read the timings
}

type claimManifest struct {
	Schema     string                 `json:"schema"`
	JournalID  string                 `json:"journal_id"`
	Generation int64                  `json:"generation"`
	NextSeq    int64                  `json:"next_seq"` // the next seq to issue when this was written
	Segments   []claimManifestSegment `json:"segments"`
}

type claimManifestSegment struct {
	Name   string `json:"name"`
	First  int64  `json:"first"`
	Closed bool   `json:"closed,omitempty"`
	Last   int64  `json:"last,omitempty"` // highest seq in it; 0: none
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// claimHead is one head file: the last acknowledged seq of the generation,
// the sha256 of its line, and the peer head the caller last set. Seq 0:
// nothing acknowledged yet.
type claimHead struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
	Peer int64  `json:"peer"`
}

// claimJournalHeads is what open found in the newest valid head file: the
// journal's own acknowledged seq and the peer head recorded with it (the
// usage log's durable head, set by the caller through setPeerHead). The
// journal makes no decision from them, and nothing in phase 2 compares the
// peer head: it is a passive field for later hardening.
type claimJournalHeads struct {
	Acked int64
	Peer  int64
}

type claimJournalEntry struct {
	kind     string
	body     []byte
	compact  bool
	snapshot []claimRecord
	queued   time.Time
	done     chan error
}

// claimSegment is the open segment, the writer's own.
type claimSegment struct {
	name       string
	first      int64
	f          *os.File
	size       int64 // bytes the writer keeps in it (whole batches, and anything a failed cut left)
	nameSynced bool  // its directory synced since it was created
	listed     bool  // the manifest on disk lists it
	cutFailed  bool  // a failed batch could not be taken back: roll before the next
}

type claimJournal struct {
	stateDir, dir string
	id            string
	disk          claimJournalDisk
	segmentMax    int64
	observe       func(claimJournalTiming)

	mu       sync.Mutex // the journal's own: the queue and the fields below; never held for disk I/O
	wake     *sync.Cond
	queue    []*claimJournalEntry
	closing  bool
	refuse   error         // set when incomplete: append and compact refuse with it
	atOpen   []claimRecord // the records open found, until replay
	replayed bool
	bytes    int64 // bytes in the live generation's segments
	peer     int64 // the peer head the next head file write records
	done     chan struct{}
	heads    claimJournalHeads // what open found
	lockFile *os.File          // claims/ held with an exclusive flock from open to close

	// The writer's own (open's, before the writer starts).
	gen            int64
	genDir         string
	man            claimManifest
	seg            *claimSegment
	nextSeq        int64
	chain          string      // sha256 of the generation's last line kept: the next line's prev
	voids          [][2]int64  // seqs of failed batches, withdrawn by the next batch's first line
	head           [2]*os.File // ack-head-a and ack-head-b, each written in place
	headSeq        [2]int64    // what each head file durably holds; -1: not known to be durable
	currentPending bool        // CURRENT renamed, claims/ not yet synced: no record until it is
	halted         error       // the writer cannot tell which generation CURRENT names: every batch fails
	errLog         time.Time
	errCount       int64
}

func claimGenName(n int64) string { return "gen-" + strconv.FormatInt(n, 10) }

func claimSegmentName(first int64) string { return fmt.Sprintf("%020d.jsonl", first) }

// openClaimJournal opens or creates the journal in stateDir, and returns the
// acknowledged head and peer head the newest valid head file holds. On an
// incomplete journal it returns the journal read only together with an error
// that matches errClaimJournalIncomplete; any other error means no journal.
func openClaimJournal(stateDir string) (*claimJournal, claimJournalHeads, error) {
	return openClaimJournalWith(stateDir, claimJournalOptions{})
}

func openClaimJournalWith(stateDir string, o claimJournalOptions) (*claimJournal, claimJournalHeads, error) {
	j, err := openClaimJournalAt(stateDir, o)
	if j == nil {
		return nil, claimJournalHeads{}, err
	}
	return j, j.heads, err
}

func openClaimJournalAt(stateDir string, o claimJournalOptions) (*claimJournal, error) {
	if stateDir == "" {
		return nil, errors.New("claim journal: no state_dir")
	}
	j := newClaimJournal(stateDir, o)
	out, err := j.openLocked()
	if out == nil {
		j.unlock() // a failed open gives the lock back
	}
	return out, err
}

func newClaimJournal(stateDir string, o claimJournalOptions) *claimJournal {
	j := &claimJournal{stateDir: stateDir, dir: filepath.Join(stateDir, claimJournalDirName),
		disk: o.disk.withDefaults(), segmentMax: o.segmentMax, observe: o.observe}
	if j.segmentMax <= 0 {
		j.segmentMax = claimSegmentMaxBytes
	}
	j.wake = sync.NewCond(&j.mu)
	return j
}

// claimLook is one look at the two names that decide an open.
type claimLook struct {
	id     string
	hasID  bool        // claims.id holds a journal id
	dir    os.FileInfo // nil: claims/ is not there
	dirErr error
}

// look reads claims.id and then stats claims/, in that order. claims/ is
// made before claims.id is ever written, so a valid claims.id read before
// claims/ is found missing means claims/ was removed, not that another
// open is still making it.
func (j *claimJournal) look() (claimLook, error) {
	var lk claimLook
	id, err := readClaimText(filepath.Join(j.stateDir, claimJournalIDName))
	switch {
	case err == nil && claimIDRE.MatchString(id):
		lk.id, lk.hasID = id, true
	case err == nil:
		// claims.id is only ever renamed into place whole; one that does
		// not parse counts as missing.
		log.Printf("claim journal: state_dir/claims.id does not hold a journal id; treated as missing")
	case !errors.Is(err, fs.ErrNotExist):
		return lk, err
	}
	j.disk.step("open-look-between")
	lk.dir, lk.dirErr = os.Stat(j.dir)
	if lk.dirErr != nil && !errors.Is(lk.dirErr, fs.ErrNotExist) {
		return lk, lk.dirErr
	}
	if lk.dirErr == nil && !lk.dir.IsDir() {
		return lk, fmt.Errorf("claim journal: %s is not a directory", j.dir)
	}
	return lk, nil
}

// openLocked decides how to open. Invariant: nothing here reads, writes,
// syncs or removes anything inside claims/ unless j.lockFile is held, and it
// decides only from a look made after the lock was taken. The one path
// without the lock is a look that finds a valid claims.id and no claims/: it
// reports incomplete and touches nothing.
func (j *claimJournal) openLocked() (*claimJournal, error) {
	for attempt := 0; attempt < 3; attempt++ {
		lk, err := j.look()
		if err != nil {
			return nil, err
		}
		if lk.hasID && lk.dir == nil {
			return j.readOnly([]string{"state_dir/claims.id exists without claims/"}, nil)
		}
		if lk.dir == nil {
			// A first start: claims/ is made so that it can be locked before
			// anything else happens in it.
			if err := os.MkdirAll(j.dir, 0o700); err != nil {
				return nil, err
			}
		}
		if err := j.lock(); err != nil {
			return nil, err
		}
		j.disk.step("open-locked")
		// Decide again from a fresh look made with the lock held, and make
		// sure the lock sits on the claims/ the path names now: a claims/
		// removed and made again between the look and the lock would leave
		// it on a dead directory.
		lk, err = j.look()
		if err != nil {
			return nil, err
		}
		if lk.dir != nil {
			if held, serr := j.lockFile.Stat(); serr == nil && os.SameFile(held, lk.dir) {
				return j.decide(lk)
			}
		}
		log.Printf("claim journal: %s was replaced while it was being locked; looking again", j.dir)
		j.unlock()
	}
	return nil, fmt.Errorf("claim journal: %s kept changing while it was being locked; open again", j.dir)
}

// decide opens from a look made with the lock held on the claims/ it saw.
func (j *claimJournal) decide(lk claimLook) (*claimJournal, error) {
	if !lk.hasID {
		held, err := claimDirHoldsRecords(j.dir)
		if err != nil {
			return nil, err
		}
		if held {
			return j.load("", []string{"state_dir/claims.id is missing while claims/ holds records"})
		}
		// A first start, or an initialization that stopped before claims.id:
		// no record was ever accepted, so it is discarded and redone.
		if err := j.create(); err != nil {
			return nil, err
		}
		j.start()
		return j, nil
	}
	return j.load(lk.id, nil)
}

// lock takes an exclusive, non-blocking flock on claims/, which must exist.
func (j *claimJournal) lock() error {
	f, err := os.Open(j.dir)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("%w: %s is held by another open journal", errClaimJournalLocked, j.dir)
		}
		return fmt.Errorf("claim journal: lock of %s: %w", j.dir, err)
	}
	j.lockFile = f
	j.disk.onLock(f)
	return nil
}

// unlock gives the lock back. Closing the descriptor releases the flock.
func (j *claimJournal) unlock() {
	if j.lockFile != nil {
		_ = j.lockFile.Close()
		j.lockFile = nil
	}
}

// requireLock is the guard create and load start with: they read, write,
// sync and remove inside claims/, which only the holder of its lock may do.
func (j *claimJournal) requireLock() error {
	if j.lockFile == nil {
		return errClaimJournalNotLocked
	}
	return nil
}

func readClaimText(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// claimDirHoldsRecords reports whether any segment of any generation in dir
// holds bytes.
func claimDirHoldsRecords(dir string) (bool, error) {
	gens, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, g := range gens {
		if !g.IsDir() || !claimGenRE.MatchString(g.Name()) {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(dir, g.Name()))
		if err != nil {
			return false, err
		}
		for _, e := range entries {
			if !e.Type().IsRegular() || !claimSegmentRE.MatchString(e.Name()) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				return false, err
			}
			if info.Size() > 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// claimJournalAncestors is, top down, every ancestor of dir up to the root.
func claimJournalAncestors(dir string) []string {
	var out []string
	for d := filepath.Clean(dir); ; {
		p := filepath.Dir(d)
		if p == d {
			return out
		}
		out = append([]string{p}, out...)
		d = p
	}
}

// syncInitChain syncs, top down, every ancestor of claims/ the journal can
// open, whether or not it existed before this open. Until claims.id is
// durable nothing tells which of them an earlier attempt created: its
// MkdirAll may have made them and then failed to sync one, and they exist
// now. A directory the journal cannot open it did not create (it makes its
// directories 0700 for itself), and a read-only one holds no entry it added.
func (j *claimJournal) syncInitChain() error {
	for _, d := range claimJournalAncestors(j.dir) {
		f, err := os.Open(d)
		if errors.Is(err, fs.ErrPermission) {
			continue
		}
		if err != nil {
			return fmt.Errorf("claim journal: open of %s to sync it: %w", d, err)
		}
		_ = f.Close()
		if err := j.disk.syncDir(d); err != nil && !errors.Is(err, syscall.EROFS) {
			return fmt.Errorf("claim journal: sync of %s before initialization: %w", d, err)
		}
	}
	return nil
}

// create makes a new journal in the initialization order: claims/ and every
// ancestor synced top down, gen-1/ and its files, CURRENT, then claims.id
// last. A crash part way leaves no claims.id and no record: the next open
// discards it and starts again, syncing the ancestors again.
func (j *claimJournal) create() error {
	if err := j.requireLock(); err != nil {
		return err
	}
	if err := os.MkdirAll(j.dir, 0o700); err != nil {
		return err
	}
	if err := j.syncInitChain(); err != nil {
		return err
	}
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return err
	}
	cleared := false
	for _, e := range entries {
		n := e.Name()
		if claimGenRE.MatchString(n) || n == claimCurrentName || n == claimCurrentName+".tmp" {
			if err := os.RemoveAll(filepath.Join(j.dir, n)); err != nil {
				return err
			}
			cleared = true
		}
	}
	if cleared {
		log.Printf("claim journal: %s held an initialization that never finished; starting again", j.dir)
	}
	// A leftover claims.id.tmp needs nothing here: writing claims.id below
	// truncates and renames that same temporary file.
	j.disk.step("init-claims-dir")
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	j.id = hex.EncodeToString(raw[:])
	man, err := j.writeGeneration(1, 1, nil, claimHead{Hash: claimGenesis}, "init")
	if err != nil {
		return err
	}
	if _, err := j.writeDurable(j.dir, claimCurrentName, []byte(claimGenName(1)+"\n"), "init-current"); err != nil {
		return err
	}
	if _, err := j.writeDurable(j.stateDir, claimJournalIDName, []byte(j.id+"\n"), "init-claims-id"); err != nil {
		return err
	}
	files, err := j.openHeads(1)
	if err != nil {
		return err
	}
	j.adoptGeneration(1, man, claimGenesis, [2]int64{0, 0}, files)
	j.nextSeq = 1
	log.Printf("claim journal: created %s (id %s)", j.dir, j.id)
	return nil
}

// openHeads opens generation n's two head files for writing: everything the
// writer needs to adopt it. A head file that is gone (the other one is
// valid, or open would not get here) is made again empty: it counts as the
// lower one and the next batch writes it.
func (j *claimJournal) openHeads(n int64) ([2]*os.File, error) {
	dir := filepath.Join(j.dir, claimGenName(n))
	var files [2]*os.File
	closeAll := func() {
		for _, g := range files {
			if g != nil {
				_ = g.Close()
			}
		}
	}
	made := false
	for i, name := range claimHeadNames {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			made = true
		}
		f, err := j.disk.open(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			closeAll()
			return [2]*os.File{}, fmt.Errorf("claim journal: open of %s/%s: %w", claimGenName(n), name, err)
		}
		files[i] = f
	}
	if made {
		if err := j.disk.syncDir(dir); err != nil {
			closeAll()
			return [2]*os.File{}, fmt.Errorf("claim journal: sync of %s after making a head file again: %w", claimGenName(n), err)
		}
	}
	return files, nil
}

// adoptGeneration makes generation n the writer's, with head files opened by
// openHeads. It cannot fail, so a compaction acquires everything first and
// adopts right after CURRENT names the new generation.
func (j *claimJournal) adoptGeneration(n int64, man claimManifest, chain string, headSeq [2]int64, files [2]*os.File) {
	for _, f := range j.head {
		if f != nil {
			_ = f.Close()
		}
	}
	j.gen, j.genDir, j.man, j.chain, j.head, j.headSeq = n, filepath.Join(j.dir, claimGenName(n)), man, chain, files, headSeq
}

// writeGeneration writes gen-n whole before anything names it: the snapshot
// segment (when buf holds records, first being its first seq), manifest,
// both head files (at head) and journal-id, each fsynced, then the
// directory. steps names the crash points.
func (j *claimJournal) writeGeneration(n, first int64, buf []byte, head claimHead, steps string) (claimManifest, error) {
	dir := filepath.Join(j.dir, claimGenName(n))
	if err := os.RemoveAll(dir); err != nil { // an earlier attempt that never committed
		return claimManifest{}, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return claimManifest{}, err
	}
	if err := j.disk.syncDir(j.dir); err != nil {
		return claimManifest{}, fmt.Errorf("claim journal: sync of claims/ after creating %s: %w", claimGenName(n), err)
	}
	j.disk.step(steps + "-gen-dir")
	man := claimManifest{Schema: claimManifestSchema, JournalID: j.id, Generation: n, NextSeq: first}
	if len(buf) > 0 {
		name := claimSegmentName(first)
		if err := j.writeSynced(filepath.Join(dir, name), buf); err != nil {
			return claimManifest{}, err
		}
		j.disk.step(steps + "-segment")
		man.Segments = []claimManifestSegment{{Name: name, First: first, Closed: true, Last: head.Seq, Size: int64(len(buf)), SHA256: claimSHA256(buf)}}
		man.NextSeq = head.Seq + 1
	}
	rawMan, err := json.Marshal(man)
	if err != nil {
		return claimManifest{}, err
	}
	if err := j.writeSynced(filepath.Join(dir, claimManifestName), append(rawMan, '\n')); err != nil {
		return claimManifest{}, err
	}
	j.disk.step(steps + "-manifest")
	rec := make([]byte, claimHeadFileBytes)
	if err := encodeClaimHead(rec, head); err != nil {
		return claimManifest{}, err
	}
	for _, name := range claimHeadNames {
		if err := j.writeSynced(filepath.Join(dir, name), rec); err != nil {
			return claimManifest{}, err
		}
		j.disk.step(steps + "-" + name)
	}
	if err := j.writeSynced(filepath.Join(dir, claimJournalIDInGen), []byte(j.id+"\n")); err != nil {
		return claimManifest{}, err
	}
	j.disk.step(steps + "-journal-id")
	if err := j.disk.syncDir(dir); err != nil {
		return claimManifest{}, fmt.Errorf("claim journal: sync of %s: %w", claimGenName(n), err)
	}
	j.disk.step(steps + "-gen-synced")
	return man, nil
}

func (j *claimJournal) writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := j.disk.syncFile(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// writeDurable replaces dir/name by temporary file, fsync, rename, directory
// fsync. renamed: the new name is in place (though maybe not durable) even if
// err is set. steps names the crash points ("" for none).
func (j *claimJournal) writeDurable(dir, name string, data []byte, steps string) (renamed bool, err error) {
	step := func(s string) {
		if steps != "" {
			j.disk.step(steps + s)
		}
	}
	tmp := filepath.Join(dir, name+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return false, err
	}
	step("-created")
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return false, err
	}
	if err := j.disk.syncFile(f); err != nil {
		_ = f.Close()
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	step("-synced")
	if err := j.disk.rename(tmp, filepath.Join(dir, name)); err != nil {
		return false, err
	}
	step("-renamed")
	if err := j.disk.syncDir(dir); err != nil {
		return true, fmt.Errorf("claim journal: sync of %s after %s: %w", dir, name, err)
	}
	step("-committed")
	return true, nil
}

func (j *claimJournal) writeManifest(steps string) error {
	j.man.NextSeq = j.nextSeq
	raw, err := json.Marshal(j.man)
	if err != nil {
		return err
	}
	_, err = j.writeDurable(j.genDir, claimManifestName, append(raw, '\n'), steps)
	return err
}

// claimLoaded is one segment as open found it.
type claimLoaded struct {
	raw  []byte
	scan claimScan
}

// load checks an existing journal (pre: reasons found before) and opens it,
// or returns it read only when it cannot be proven whole. id "": claims.id
// is missing.
func (j *claimJournal) load(id string, pre []string) (*claimJournal, error) {
	if err := j.requireLock(); err != nil {
		return nil, err
	}
	reasons := append([]string(nil), pre...)
	cur, err := readClaimText(filepath.Join(j.dir, claimCurrentName))
	if errors.Is(err, fs.ErrNotExist) {
		return j.readOnly(append(reasons, "claims/CURRENT is missing"), nil)
	}
	if err != nil {
		return nil, err
	}
	m := claimGenRE.FindStringSubmatch(cur)
	if m == nil {
		return j.readOnly(append(reasons, fmt.Sprintf("claims/CURRENT holds %q, not a generation", cur)), nil)
	}
	gen, _ := strconv.ParseInt(m[1], 10, 64)
	genDir := filepath.Join(j.dir, cur)
	if info, err := os.Stat(genDir); err != nil || !info.IsDir() {
		return j.readOnly(append(reasons, fmt.Sprintf("claims/CURRENT names %s, which is missing", cur)), nil)
	}
	inGen, err := readClaimText(filepath.Join(genDir, claimJournalIDInGen))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		reasons = append(reasons, cur+"/journal-id is missing")
	case err != nil:
		return nil, err
	case id != "" && inGen != id:
		reasons = append(reasons, fmt.Sprintf("%s/journal-id %q is not state_dir/claims.id %q", cur, inGen, id))
	}
	if id == "" {
		id = inGen
	}
	j.id = id
	rawMan, err := os.ReadFile(filepath.Join(genDir, claimManifestName))
	if errors.Is(err, fs.ErrNotExist) {
		return j.readOnly(append(reasons, cur+"/manifest.json is missing"), nil)
	}
	if err != nil {
		return nil, err
	}
	var man claimManifest
	if json.Unmarshal(rawMan, &man) != nil || man.Schema != claimManifestSchema {
		return j.readOnly(append(reasons, cur+"/manifest.json is not a claim manifest"), nil)
	}
	if man.JournalID != id || man.Generation != gen {
		reasons = append(reasons, fmt.Sprintf("%s/manifest.json is journal %q generation %d", cur, man.JournalID, man.Generation))
	}
	if p := man.orderProblem(); p != "" {
		return j.readOnly(append(reasons, p), nil)
	}
	head, headSeq, headErr := readClaimHeadsWith(genDir, j.disk.readHead)
	if errors.Is(headErr, errClaimHeadUnreadable) {
		// An I/O error is not loss: open fails and may be tried again, as for
		// any other file it cannot read.
		return nil, fmt.Errorf("claim journal: %s: %w", cur, headErr)
	}
	if headErr != nil {
		reasons = append(reasons, cur+": "+headErr.Error())
	} else {
		j.heads = claimJournalHeads{Acked: head.Seq, Peer: head.Peer}
	}

	listed := map[string]bool{}
	loaded := map[string]*claimLoaded{}
	var lines []claimLine
	var after, top int64
	for _, s := range man.Segments {
		listed[s.Name] = true
		raw, err := os.ReadFile(filepath.Join(genDir, s.Name))
		if errors.Is(err, fs.ErrNotExist) {
			reasons = append(reasons, fmt.Sprintf("segment %s/%s is listed but missing", cur, s.Name))
			continue
		}
		if err != nil {
			return nil, err
		}
		sc := scanClaimSegment(s.Name, raw, max(after, s.First-1), true)
		loaded[s.Name] = &claimLoaded{raw: raw, scan: sc}
		if s.Closed {
			switch {
			case int64(len(raw)) < s.Size || sc.last < s.Last:
				reasons = append(reasons, fmt.Sprintf("segment %s/%s is short: %d bytes and last seq %d, the manifest says %d and %d", cur, s.Name, len(raw), sc.last, s.Size, s.Last))
			case int64(len(raw)) != s.Size || claimSHA256(raw) != s.SHA256:
				reasons = append(reasons, fmt.Sprintf("segment %s/%s changed: its sha256 is not the manifest's", cur, s.Name))
			}
		}
		lines = append(lines, sc.lines...)
		after = max(after, sc.last)
		top = max(top, sc.last, s.First)
	}
	// Walk the chain. A line whose prev is not the line before it is off the
	// chain and skipped; the valid head must be on the chain, with its hash.
	chain, onHead := claimGenesis, false
	var kept []claimRecord
	for _, l := range lines {
		if l.prev != chain {
			log.Printf("claim journal: %s seq %d is off the chain (its predecessor did not survive), skipped", cur, l.Seq)
			continue
		}
		chain = l.hash
		kept = append(kept, l.claimRecord)
		if headErr == nil && l.Seq == head.Seq {
			onHead = true
			if l.hash != head.Hash {
				reasons = append(reasons, fmt.Sprintf("%s: the line at head seq %d is not the acknowledged one", cur, head.Seq))
			}
		}
	}
	if headErr == nil && head.Seq > 0 && !onHead {
		reasons = append(reasons, fmt.Sprintf("%s: the chain ends before head seq %d: acknowledged records are missing or changed", cur, head.Seq))
	}

	var debris, debrisGen, debrisTop []string
	entries, err := os.ReadDir(genDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case !e.Type().IsRegular():
		case strings.HasSuffix(name, ".tmp"):
			debrisGen = append(debrisGen, name)
		case claimSegmentRE.MatchString(name) && !listed[name]:
			info, err := e.Info()
			if err != nil {
				return nil, err
			}
			if info.Size() == 0 {
				debrisGen = append(debrisGen, name) // created, never listed, took nothing
			} else {
				reasons = append(reasons, fmt.Sprintf("segment %s/%s holds %d bytes and is not listed", cur, name, info.Size()))
			}
		}
	}
	tops, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, err
	}
	for _, e := range tops {
		name := e.Name()
		if (claimGenRE.MatchString(name) && name != cur) || name == claimCurrentName+".tmp" {
			debrisTop = append(debrisTop, name) // unfinished (newer) or obsolete (older)
		}
	}
	records := withoutVoided(kept)
	if len(reasons) > 0 {
		return j.readOnly(reasons, records)
	}

	// A crash can leave a rename visible but not yet durable: claims.id's at
	// the end of an initialization whose state_dir sync failed, or CURRENT's
	// after a compaction whose claims/ sync did not run. Both names are made
	// durable before anything is removed as obsolete and before any record
	// is acknowledged under them.
	if err := j.disk.syncDir(j.stateDir); err != nil {
		return nil, fmt.Errorf("claim journal: sync of state_dir before using claims.id: %w", err)
	}
	if err := j.disk.syncDir(j.dir); err != nil {
		return nil, fmt.Errorf("claim journal: sync of claims/ before using CURRENT: %w", err)
	}
	j.disk.step("open-names-synced")

	sort.Strings(debrisGen)
	sort.Strings(debrisTop)
	for _, name := range debrisGen {
		if err := os.Remove(filepath.Join(genDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		debris = append(debris, cur+"/"+name)
	}
	if len(debrisGen) > 0 {
		if err := j.disk.syncDir(genDir); err != nil {
			return nil, fmt.Errorf("claim journal: sync of %s after removing crash leftovers: %w", cur, err)
		}
	}
	for _, name := range debrisTop {
		if err := os.RemoveAll(filepath.Join(j.dir, name)); err != nil {
			return nil, err
		}
		debris = append(debris, name)
	}
	if len(debrisTop) > 0 {
		if err := j.disk.syncDir(j.dir); err != nil {
			return nil, fmt.Errorf("claim journal: sync of claims/ after removing crash leftovers: %w", err)
		}
	}
	_ = os.Remove(filepath.Join(j.stateDir, claimJournalIDName+".tmp"))
	for _, d := range debris {
		log.Printf("claim journal: removed %s, left by a crash (not part of %s)", d, cur)
	}
	files, err := j.openHeads(gen)
	if err != nil {
		return nil, err
	}
	j.adoptGeneration(gen, man, chain, headSeq, files)
	// From here a failed open returns no journal, so it closes what it holds:
	// a caller that retries through an I/O failure must not leak descriptors.
	fail := func(err error) (*claimJournal, error) {
		j.shut()
		return nil, err
	}
	j.peer = head.Peer
	j.atOpen = records
	j.nextSeq = max(man.NextSeq, top+1)
	for _, l := range loaded {
		j.bytes += int64(len(l.raw))
	}
	// The previous run's open segment is synced (its last batch may be only in
	// the page cache) and closed as found; this run starts a new one.
	if n := len(j.man.Segments); n > 0 && !j.man.Segments[n-1].Closed {
		s := &j.man.Segments[n-1]
		f, err := os.OpenFile(filepath.Join(genDir, s.Name), os.O_RDWR, 0)
		if err != nil {
			return fail(err)
		}
		err = j.disk.syncFile(f)
		_ = f.Close()
		if err != nil {
			return fail(fmt.Errorf("claim journal: sync of %s before closing it: %w", s.Name, err))
		}
		found := loaded[s.Name]
		*s = claimManifestSegment{Name: s.Name, First: s.First, Closed: true, Last: found.scan.last,
			Size: int64(len(found.raw)), SHA256: claimSHA256(found.raw)}
		j.nextSeq = max(j.nextSeq, s.First+1)
		if err := j.writeManifest(""); err != nil {
			return fail(err)
		}
	}
	log.Printf("claim journal: %s %s, %d segments, %d records, head %d, next seq %d", j.dir, cur, len(man.Segments), len(records), head.Seq, j.nextSeq)
	j.start()
	return j, nil
}

func (m claimManifest) orderProblem() string {
	var prev int64
	for i, s := range m.Segments {
		if !claimSegmentRE.MatchString(s.Name) || s.Name != claimSegmentName(s.First) {
			return fmt.Sprintf("manifest entry %d (%q) does not name its first seq", i, s.Name)
		}
		if s.First <= prev {
			return fmt.Sprintf("manifest segment %s is out of order", s.Name)
		}
		if !s.Closed && i != len(m.Segments)-1 {
			return fmt.Sprintf("manifest lists %s open before the last segment", s.Name)
		}
		prev = max(s.First, s.Last)
	}
	return ""
}

// readOnly marks the journal incomplete: replay yields records, append and
// compact refuse, nothing runs and no file changes.
func (j *claimJournal) readOnly(reasons []string, records []claimRecord) (*claimJournal, error) {
	err := &claimJournalIncompleteError{reasons: reasons}
	j.refuse = err
	j.atOpen = records
	log.Printf("claim journal: ALARM %s: %v; claims stay off and no file is changed until a person looks", j.dir, err)
	return j, err
}

// claimLine is one record line as read back.
type claimLine struct {
	claimRecord
	prev, hash string
}

// claimScan is what one segment's bytes hold.
type claimScan struct {
	lines []claimLine
	last  int64 // highest seq in it; 0: none
}

type claimLineJSON struct {
	Schema string          `json:"schema"`
	Seq    int64           `json:"seq"`
	Prev   string          `json:"prev"`
	Kind   string          `json:"kind"`
	Body   json.RawMessage `json:"body"`
}

// scanClaimSegment reads one segment's lines. A last line without its
// newline is torn (its batch never synced) and skipped whole; a line that is
// not a record, or whose seq is not above after, is skipped. logIt: say so.
func scanClaimSegment(name string, raw []byte, after int64, logIt bool) claimScan {
	var sc claimScan
	for n := 1; len(raw) > 0; n++ {
		i := bytes.IndexByte(raw, '\n')
		if i < 0 {
			if logIt {
				log.Printf("claim journal: %s line %d: torn last line skipped (%d bytes)", name, n, len(raw))
			}
			break
		}
		line := raw[:i]
		raw = raw[i+1:]
		var l claimLineJSON
		if json.Unmarshal(line, &l) != nil || l.Schema != claimRecordSchema || l.Kind == "" || l.Seq <= 0 || len(l.Prev) != 64 {
			if logIt {
				log.Printf("claim journal: %s line %d: not a claim record, skipped", name, n)
			}
			continue
		}
		if l.Seq <= after {
			if logIt {
				log.Printf("claim journal: %s line %d: seq %d is not after %d, skipped", name, n, l.Seq, after)
			}
			continue
		}
		after, sc.last = l.Seq, l.Seq
		sc.lines = append(sc.lines, claimLine{claimRecord: claimRecord{Seq: l.Seq, Kind: l.Kind, Body: l.Body}, prev: l.Prev, hash: claimSHA256(line)})
	}
	return sc
}

type claimVoidBody struct {
	Seqs [][2]int64 `json:"seqs"`
}

// withoutVoided drops the journal's own lines and every seq a void line
// withdrew.
func withoutVoided(recs []claimRecord) []claimRecord {
	var voids [][2]int64
	for _, r := range recs {
		if r.Kind != claimVoidKind {
			continue
		}
		var v claimVoidBody
		if json.Unmarshal(r.Body, &v) == nil {
			voids = append(voids, v.Seqs...)
		}
	}
	var out []claimRecord
	for _, r := range recs {
		if strings.HasPrefix(r.Kind, "journal_") || claimSeqVoided(voids, r.Seq) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func claimSeqVoided(voids [][2]int64, seq int64) bool {
	for _, v := range voids {
		if seq >= v[0] && seq <= v[1] {
			return true
		}
	}
	return false
}

func claimSHA256(p []byte) string {
	sum := sha256.Sum256(p)
	return hex.EncodeToString(sum[:])
}

// encodeClaimHead writes h as one head file's bytes: its JSON padded with
// spaces, a space, and the hex sha256 of the padded JSON, so a spoiled or
// short file is refused.
func encodeClaimHead(slot []byte, h claimHead) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(raw) > claimHeadBodyBytes {
		return fmt.Errorf("claim journal: a head file is %d bytes, more than %d", len(raw), claimHeadBodyBytes)
	}
	body := slot[:claimHeadBodyBytes]
	copy(body, raw)
	for i := len(raw); i < len(body); i++ {
		body[i] = ' '
	}
	slot[claimHeadBodyBytes] = ' '
	sum := sha256.Sum256(body)
	hex.Encode(slot[claimHeadBodyBytes+1:], sum[:])
	return nil
}

func decodeClaimHead(slot []byte) (claimHead, bool) {
	var h claimHead
	if len(slot) != claimHeadFileBytes || slot[claimHeadBodyBytes] != ' ' {
		return h, false
	}
	body := slot[:claimHeadBodyBytes]
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != string(slot[claimHeadBodyBytes+1:]) {
		return h, false
	}
	if json.Unmarshal(bytes.TrimRight(body, " "), &h) != nil || h.Seq < 0 || h.Peer < 0 || len(h.Hash) != 64 {
		return h, false
	}
	return h, true
}

// errClaimHeadUnreadable marks a head file that could not be read at all (an
// I/O error), as opposed to one read and found missing, short or spoiled.
var errClaimHeadUnreadable = errors.New("claim journal: a head file cannot be read")

// readClaimHeads returns the valid head file of dir with the higher seq, and
// what each file holds (-1: missing or not valid).
func readClaimHeads(dir string) (claimHead, [2]int64, error) {
	return readClaimHeadsWith(dir, os.ReadFile)
}

// readClaimHeadsWith is readClaimHeads with its file read given. A file that
// cannot be read is no verdict on either head: the call fails with
// errClaimHeadUnreadable rather than fall back on the other file, which may
// hold the older head and so accept a tail shorter than what was
// acknowledged.
func readClaimHeadsWith(dir string, read func(string) ([]byte, error)) (claimHead, [2]int64, error) {
	seqs := [2]int64{-1, -1}
	var best claimHead
	found := false
	for i, name := range claimHeadNames {
		raw, err := read(filepath.Join(dir, name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return claimHead{}, seqs, fmt.Errorf("%w: %s: %w", errClaimHeadUnreadable, name, err)
		}
		h, ok := decodeClaimHead(raw)
		if !ok {
			continue
		}
		seqs[i] = h.Seq
		if !found || h.Seq > best.Seq {
			best, found = h, true
		}
	}
	if !found {
		return claimHead{}, seqs, errors.New("neither head file is valid (missing, short or spoiled)")
	}
	return best, seqs, nil
}

func (j *claimJournal) start() {
	j.done = make(chan struct{})
	go j.run()
}

// checkClaimRecord returns the record's kind and its body in compact form.
func checkClaimRecord(r claimRecord) (string, []byte, error) {
	if !claimKindRE.MatchString(r.Kind) || strings.HasPrefix(r.Kind, "journal_") {
		return "", nil, fmt.Errorf("claim journal: kind %q is not a record kind", r.Kind)
	}
	if len(r.Body) == 0 {
		return r.Kind, nil, nil
	}
	if len(r.Body) > claimRecordMaxBytes {
		return "", nil, fmt.Errorf("claim journal: %s body is %d bytes, more than %d", r.Kind, len(r.Body), claimRecordMaxBytes)
	}
	var b bytes.Buffer
	if err := json.Compact(&b, r.Body); err != nil {
		return "", nil, fmt.Errorf("claim journal: %s body is not JSON: %w", r.Kind, err)
	}
	return r.Kind, b.Bytes(), nil
}

// append queues one record (one line: every fact in it survives together).
// The channel closes once the record is acknowledged (a receive gives nil),
// or carries an error. The error is indeterminate: the record may still be
// durable and come back at replay (see "Caller rules"), so a caller never
// frees or re-grants on it, keys records by claim or request id, and settles
// the outcome at replay. The caller waits with its own deadline.
func (j *claimJournal) append(rec claimRecord) <-chan error {
	done := make(chan error, 1)
	kind, body, err := checkClaimRecord(rec)
	if err != nil {
		done <- err
		close(done)
		return done
	}
	j.enqueue(&claimJournalEntry{kind: kind, body: body, queued: time.Now(), done: done})
	return done
}

// compact commits snapshot whole as the next generation. It replaces every
// record appended before this call; records appended after it go into the
// new generation. Build snapshot only after every earlier append has been
// acknowledged. The channel works as append's, and an error is
// indeterminate in the same way: it can come after the new generation was
// committed.
func (j *claimJournal) compact(snapshot []claimRecord) <-chan error {
	done := make(chan error, 1)
	snap := make([]claimRecord, 0, len(snapshot))
	for _, r := range snapshot {
		kind, body, err := checkClaimRecord(r)
		if err != nil {
			done <- err
			close(done)
			return done
		}
		snap = append(snap, claimRecord{Kind: kind, Body: body})
	}
	j.enqueue(&claimJournalEntry{compact: true, snapshot: snap, queued: time.Now(), done: done})
	return done
}

func (j *claimJournal) enqueue(e *claimJournalEntry) {
	j.mu.Lock()
	defer j.mu.Unlock()
	switch {
	case j.refuse != nil:
		e.done <- j.refuse
		close(e.done)
	case j.closing:
		e.done <- errClaimJournalClosed
		close(e.done)
	default:
		j.queue = append(j.queue, e)
		j.wake.Signal()
	}
}

// replay yields, in seq order, the records the live generation held when the
// journal was opened (withdrawn seqs, lines off the chain and the journal's
// own lines left out). It runs once.
func (j *claimJournal) replay(fn func(claimRecord) error) error {
	j.mu.Lock()
	recs, again := j.atOpen, j.replayed
	j.atOpen, j.replayed = nil, true
	j.mu.Unlock()
	if again {
		return errors.New("claim journal: replay runs once, after open")
	}
	for _, r := range recs {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

// size is the bytes in the live generation's segments.
func (j *claimJournal) size() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.bytes
}

// close writes what is queued, then stops the writer. Appends after it fail.
func (j *claimJournal) close() error {
	j.mu.Lock()
	if j.done == nil { // read only: nothing runs
		j.unlock()
		j.mu.Unlock()
		return nil
	}
	j.closing = true
	j.wake.Broadcast()
	done := j.done
	j.mu.Unlock()
	<-done
	// The writer has stopped and closed its files: only now may another open
	// take claims/.
	j.mu.Lock()
	j.unlock()
	j.mu.Unlock()
	return nil
}

// take waits for work: a compaction alone, or the records queued before the
// next compaction, at most claimWriteMaxBytes of them. ok false: closed and
// drained.
func (j *claimJournal) take() (batch []*claimJournalEntry, ok bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for len(j.queue) == 0 && !j.closing {
		j.wake.Wait()
	}
	if len(j.queue) == 0 {
		return nil, false
	}
	n, size := 1, len(j.queue[0].body)+len(j.queue[0].kind)+160
	if !j.queue[0].compact {
		for n < len(j.queue) && !j.queue[n].compact {
			est := len(j.queue[n].body) + len(j.queue[n].kind) + 160
			if size+est > claimWriteMaxBytes {
				break
			}
			size += est
			n++
		}
	}
	batch = append([]*claimJournalEntry(nil), j.queue[:n]...)
	j.queue = j.queue[n:]
	if len(j.queue) == 0 {
		j.queue = nil
	}
	return batch, true
}

// halt stops every later write: appends are refused at once, and whatever is
// queued fails. It is for a writer that cannot tell which generation CURRENT
// names, so that it never acknowledges a record a restart would drop.
func (j *claimJournal) halt(err error) {
	j.halted = err
	j.mu.Lock()
	j.refuse = err
	j.mu.Unlock()
	log.Printf("claim journal: ALARM %v", err)
}

func (j *claimJournal) run() {
	defer close(j.done)
	for {
		batch, ok := j.take()
		if !ok {
			j.shut()
			return
		}
		if j.halted != nil {
			j.finish(batch, j.halted)
			continue
		}
		taken := time.Now()
		if batch[0].compact {
			err := j.compactNow(batch[0].snapshot)
			t := claimJournalTiming{Compaction: true, Records: len(batch[0].snapshot), Total: time.Since(taken), Err: err}
			j.finish(batch, err)
			j.note(t)
			continue
		}
		t := claimJournalTiming{Records: len(batch)}
		var sum time.Duration
		for _, e := range batch {
			w := taken.Sub(e.queued)
			sum += w
			t.QueueMax = max(t.QueueMax, w)
		}
		t.Queue = sum / time.Duration(len(batch))
		t.Err = j.commit(batch, &t)
		j.finish(batch, t.Err)
		j.note(t)
	}
}

func (j *claimJournal) finish(batch []*claimJournalEntry, err error) {
	if err != nil {
		j.errCount++
		if time.Since(j.errLog) >= time.Minute {
			j.errLog = time.Now()
			log.Printf("claim journal: %v (%d failures so far)", err, j.errCount)
		}
	}
	for _, e := range batch {
		if err != nil {
			e.done <- err
		}
		close(e.done)
	}
}

func (j *claimJournal) note(t claimJournalTiming) {
	if j.observe != nil {
		j.observe(t)
	}
}

func (j *claimJournal) shut() {
	if j.seg != nil {
		_ = j.seg.f.Close()
		j.seg = nil
	}
	for i, f := range j.head {
		if f != nil {
			_ = f.Close()
			j.head[i] = nil
		}
	}
}

func (j *claimJournal) addBytes(n int64) {
	j.mu.Lock()
	j.bytes += n
	j.mu.Unlock()
}

func (j *claimJournal) setBytes(n int64) {
	j.mu.Lock()
	j.bytes = n
	j.mu.Unlock()
}

// appendClaimLine appends one record line chained to prev and returns the
// line's hash, the next line's prev.
func appendClaimLine(buf []byte, seq int64, prev, kind string, body []byte) ([]byte, string) {
	start := len(buf)
	buf = append(buf, `{"schema":"`+claimRecordSchema+`","seq":`...)
	buf = strconv.AppendInt(buf, seq, 10)
	buf = append(buf, `,"prev":"`...)
	buf = append(buf, prev...)
	buf = append(buf, `","kind":"`...)
	buf = append(buf, kind...)
	buf = append(buf, '"')
	if len(body) > 0 {
		buf = append(buf, `,"body":`...)
		buf = append(buf, body...)
	}
	buf = append(buf, '}')
	hash := claimSHA256(buf[start:])
	return append(buf, '\n'), hash
}

// commit makes one batch durable and acknowledged: segment ready, one write
// (a void line for earlier failures first), the segment fsync, then ack-head's
// write and fsync. Only then may the batch be released.
func (j *claimJournal) commit(batch []*claimJournalEntry, t *claimJournalTiming) error {
	r0 := time.Now()
	err := j.ready()
	t.Roll = time.Since(r0)
	if err != nil {
		return err
	}
	seg := j.seg
	first, seq, chain := j.nextSeq, j.nextSeq, j.chain
	var buf []byte
	if len(j.voids) > 0 {
		vb, err := json.Marshal(claimVoidBody{Seqs: j.voids})
		if err != nil {
			return err
		}
		buf, chain = appendClaimLine(buf, seq, chain, claimVoidKind, vb)
		seq++
	}
	for _, e := range batch {
		buf, chain = appendClaimLine(buf, seq, chain, e.kind, e.body)
		seq++
	}
	last := seq - 1
	t.Bytes = len(buf)
	w0 := time.Now()
	err = j.disk.write(seg.f, buf)
	t.Write = time.Since(w0)
	if err == nil {
		j.disk.step("batch-written")
		s0 := time.Now()
		err = j.disk.sync(seg.f)
		t.Sync = time.Since(s0)
	}
	if err != nil {
		j.takeBack(first, last, true)
		return fmt.Errorf("claim journal: batch of %d records not durable: %w", len(batch), err)
	}
	j.disk.step("batch-synced")
	// The bytes are durable: they stay in the segment and on the chain
	// whatever happens to the head file.
	seg.size += int64(len(buf))
	j.chain = chain
	j.addBytes(int64(len(buf)))
	h0 := time.Now()
	err = j.writeHead(claimHead{Seq: last, Hash: chain, Peer: j.peerHead()})
	t.Head = time.Since(h0)
	if err != nil {
		j.takeBack(first, last, false)
		return fmt.Errorf("claim journal: batch of %d records synced but its head file not durable: %w", len(batch), err)
	}
	j.nextSeq = last + 1
	j.voids = nil
	return nil
}

// writeHead overwrites the head file holding the lower seq (a file whose
// last write did not sync counts as lowest), then fsyncs that file.
func (j *claimJournal) writeHead(h claimHead) error {
	slot := 0
	if j.headSeq[1] < j.headSeq[0] {
		slot = 1
	}
	buf := make([]byte, claimHeadFileBytes)
	if err := encodeClaimHead(buf, h); err != nil {
		return err
	}
	j.headSeq[slot] = -1
	if _, err := j.head[slot].WriteAt(buf, 0); err != nil {
		return err
	}
	j.disk.step("head-written")
	if err := j.disk.syncHead(j.head[slot]); err != nil {
		return err
	}
	j.headSeq[slot] = h.Seq
	return nil
}

// setPeerHead sets the peer head (the usage log's durable head) that every
// later head file write records; open returns the one the valid head holds.
// Nothing calls it yet.
func (j *claimJournal) setPeerHead(seq int64) {
	j.mu.Lock()
	j.peer = max(seq, 0)
	j.mu.Unlock()
}

func (j *claimJournal) peerHead() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.peer
}

// takeBack withdraws a failed batch's seqs (first to last): they are never
// issued again and the next batch's void line names them. cut: the bytes may
// not be durable, so cut them off (a segment that cannot be cut is closed as
// it is at the next batch, and the chain goes on from what it holds).
func (j *claimJournal) takeBack(first, last int64, cut bool) {
	j.nextSeq = last + 1
	if n := len(j.voids); n > 0 && j.voids[n-1][1]+1 == first {
		j.voids[n-1][1] = last
	} else {
		j.voids = append(j.voids, [2]int64{first, last})
	}
	if !cut {
		return
	}
	if err := j.disk.cut(j.seg.f, j.seg.size); err != nil {
		j.seg.cutFailed = true
		log.Printf("claim journal: %s: a failed batch could not be cut off (%v); the next batch starts a new segment", j.seg.name, err)
	}
}

// ready makes the open segment able to take a record: rolled when there is
// none, it is full or a cut failed; created and its directory synced; listed
// in the manifest. Each step is retried by the next batch after a failure.
func (j *claimJournal) ready() error {
	if j.currentPending {
		// A compaction renamed CURRENT but could not sync claims/: no record
		// goes into the new generation before that name is durable.
		if err := j.disk.syncDir(j.dir); err != nil {
			return fmt.Errorf("claim journal: sync of claims/ after a compaction: %w", err)
		}
		j.currentPending = false
	}
	if s := j.seg; s == nil || s.cutFailed || (s.listed && s.size >= j.segmentMax) {
		if err := j.roll(); err != nil {
			return err
		}
	}
	s := j.seg
	if !s.nameSynced {
		if err := j.disk.syncDir(j.genDir); err != nil {
			return fmt.Errorf("claim journal: sync of %s for new segment %s: %w", claimGenName(j.gen), s.name, err)
		}
		s.nameSynced = true
		j.disk.step("roll-dir-synced")
	}
	if !s.listed {
		j.man.Segments = append(j.man.Segments, claimManifestSegment{Name: s.name, First: s.first})
		if err := j.writeManifest("roll-manifest"); err != nil {
			j.man.Segments = j.man.Segments[:len(j.man.Segments)-1]
			return fmt.Errorf("claim journal: manifest for new segment %s: %w", s.name, err)
		}
		s.listed = true
	}
	return nil
}

func (j *claimJournal) roll() error {
	if j.seg != nil {
		if err := j.closeSegment(); err != nil {
			return err
		}
	}
	name := claimSegmentName(j.nextSeq)
	path := filepath.Join(j.genDir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) && !j.listed(name) {
		// An empty file of this name that the manifest does not list is a
		// segment that took nothing and could not be removed: open treats it
		// as debris, and the writer takes it over instead of failing every
		// later batch on its name.
		if info, serr := os.Stat(path); serr == nil && info.Mode().IsRegular() && info.Size() == 0 {
			f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		}
	}
	if err != nil {
		return fmt.Errorf("claim journal: new segment %s: %w", name, err)
	}
	j.seg = &claimSegment{name: name, first: j.nextSeq, f: f}
	j.disk.step("roll-created")
	return nil
}

// listed reports whether the manifest in memory names segment name.
func (j *claimJournal) listed(name string) bool {
	for _, s := range j.man.Segments {
		if s.Name == name {
			return true
		}
	}
	return false
}

// closeSegment syncs the open segment and records its last seq, size and
// sha256 in the manifest in memory; the next manifest write makes that
// durable. A segment never listed took no record and is removed.
func (j *claimJournal) closeSegment() error {
	s := j.seg
	path := filepath.Join(j.genDir, s.name)
	if !s.listed {
		_ = s.f.Close()
		j.seg = nil
		// If this fails the empty file stays; roll takes it over (see there)
		// and open removes it as debris.
		return j.disk.remove(path)
	}
	if err := j.disk.syncFile(s.f); err != nil {
		return fmt.Errorf("claim journal: sync of %s before closing it: %w", s.name, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	i := len(j.man.Segments) - 1
	if i < 0 || j.man.Segments[i].Name != s.name {
		return fmt.Errorf("claim journal: open segment %s is not the manifest's last", s.name)
	}
	sc := scanClaimSegment(s.name, raw, s.first-1, false)
	j.man.Segments[i] = claimManifestSegment{Name: s.name, First: s.first, Closed: true, Last: sc.last,
		Size: int64(len(raw)), SHA256: claimSHA256(raw)}
	if s.cutFailed && len(sc.lines) > 0 {
		// Whole lines of the failed batch stay: the chain goes on from the
		// segment's last line.
		j.chain = sc.lines[len(sc.lines)-1].hash
	}
	_ = s.f.Close()
	j.seg = nil
	// The next segment is named above this one even when this one took no
	// record, so two segments never share a name.
	j.nextSeq = max(j.nextSeq, s.first+1)
	return nil
}

// compactNow writes gen-N+1 whole from snap, commits CURRENT, then deletes
// gen-N. Before the CURRENT rename the live generation is untouched.
func (j *claimJournal) compactNow(snap []claimRecord) error {
	if j.seg != nil {
		if err := j.closeSegment(); err != nil {
			return err
		}
	}
	j.disk.step("compact-start")
	next := j.gen + 1
	first := j.nextSeq
	chain := claimGenesis
	var buf []byte
	for i, r := range snap {
		buf, chain = appendClaimLine(buf, first+int64(i), chain, r.Kind, r.Body)
	}
	n := int64(len(snap))
	// Burned whatever happens, so seqs never go back.
	j.nextSeq = first + n
	head := claimHead{Seq: 0, Hash: claimGenesis, Peer: j.peerHead()}
	if n > 0 {
		head.Seq, head.Hash = first+n-1, chain
	}
	nextDir := filepath.Join(j.dir, claimGenName(next))
	man, err := j.writeGeneration(next, first, buf, head, "compact")
	if err != nil {
		_ = os.RemoveAll(nextDir)
		return fmt.Errorf("claim journal: compaction %s: %w", claimGenName(next), err)
	}
	// Everything the writer needs for the new generation is acquired before
	// CURRENT names it: once it does, no record is ever acknowledged in the
	// old one.
	files, err := j.openHeads(next)
	if err != nil {
		_ = os.RemoveAll(nextDir)
		return fmt.Errorf("claim journal: compaction %s: %w", claimGenName(next), err)
	}
	renamed, err := j.writeDurable(j.dir, claimCurrentName, []byte(claimGenName(next)+"\n"), "compact-current")
	if err != nil && !renamed {
		// The rename reported failure. Read CURRENT back rather than trust
		// that: adopt whichever generation it names, or, when it cannot be
		// read, stop writing altogether.
		cur, rerr := j.disk.readBack(filepath.Join(j.dir, claimCurrentName))
		switch {
		case rerr == nil && cur == claimGenName(j.gen):
			for _, f := range files {
				_ = f.Close()
			}
			_ = os.RemoveAll(nextDir)
			return fmt.Errorf("claim journal: compaction commit: %w", err)
		case rerr == nil && cur == claimGenName(next):
			// It happened after all; go on as for a rename whose directory
			// sync failed.
		default:
			for _, f := range files {
				_ = f.Close()
			}
			j.halt(fmt.Errorf("claim journal: compaction commit failed (%v) and CURRENT cannot be read back (%v, %q): writes stop until a restart", err, rerr, cur))
			return j.halted
		}
	}
	oldDir, oldGen := j.genDir, j.gen
	j.adoptGeneration(next, man, chain, [2]int64{head.Seq, head.Seq}, files)
	j.voids = nil // the withdrawn seqs were all in the replaced generation
	j.setBytes(int64(len(buf)))
	if err != nil {
		// CURRENT names the new generation but its name may not be durable
		// yet: no record goes in before claims/ syncs (ready), and the old
		// generation stays until the next open removes it as obsolete.
		j.currentPending = true
		return fmt.Errorf("claim journal: compaction commit not durable yet: %w", err)
	}
	entries, _ := os.ReadDir(oldDir)
	for _, e := range entries {
		if err := os.Remove(filepath.Join(oldDir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Printf("claim journal: %s/%s not removed (%v); the next open removes it", claimGenName(oldGen), e.Name(), err)
		}
		j.disk.step("compact-removed")
	}
	if err := os.Remove(oldDir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("claim journal: %s not removed (%v); the next open removes it", claimGenName(oldGen), err)
	}
	if err := j.disk.syncDir(j.dir); err != nil {
		log.Printf("claim journal: sync of claims/ after a compaction: %v", err)
	}
	j.disk.step("compact-done")
	return nil
}
