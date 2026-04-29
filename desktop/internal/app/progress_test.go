package app

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"monban/internal/monban"
)

// fakeEmitter records every EmitEvent call so tests can assert which
// events fired and in what order. Concurrent-safe because workers may
// call FileDone from multiple goroutines.
type fakeEmitter struct {
	mu     sync.Mutex
	events []recordedEvent
}

type recordedEvent struct {
	name string
	data []any
}

func (f *fakeEmitter) EmitEvent(name string, data ...any) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, recordedEvent{name: name, data: data})
	return true
}

func (f *fakeEmitter) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.events))
	for i, e := range f.events {
		out[i] = e.name
	}
	return out
}

func (f *fakeEmitter) lastPayload() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.events) - 1; i >= 0; i-- {
		if len(f.events[i].data) == 1 {
			if m, ok := f.events[i].data[0].(map[string]any); ok {
				return m
			}
		}
	}
	return nil
}

// TestProgressEmitter_FileDoneCounts: counters are atomic and end at
// the expected totals after concurrent FileDone calls.
func TestProgressEmitter_FileDoneCounts(t *testing.T) {
	p := newProgressEmitterFromEmitter(nil, "lock", 100, 1024)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.FileDone(10)
		}()
	}
	wg.Wait()

	if got := p.doneFiles.Load(); got != 100 {
		t.Errorf("doneFiles = %d, want 100", got)
	}
	if got := p.doneBytes.Load(); got != 1000 {
		t.Errorf("doneBytes = %d, want 1000", got)
	}
}

// TestProgressEmitter_DoneEmitsProgressAndComplete: Done() emits one
// final progress event AND a complete event, both via the fake.
func TestProgressEmitter_DoneEmitsProgressAndComplete(t *testing.T) {
	fake := &fakeEmitter{}
	p := newProgressEmitterFromEmitter(fake, "unlock", 5, 500)

	p.FileDone(100)
	p.FileDone(100)
	p.FileDone(100)
	p.FileDone(100)
	p.FileDone(100)

	p.Done()

	names := fake.names()
	if len(names) == 0 {
		t.Fatal("expected at least one event, got none")
	}
	last := names[len(names)-1]
	if last != "unlock:complete" {
		t.Errorf("last event = %q, want unlock:complete", last)
	}

	// The penultimate event must be the final progress emit.
	if len(names) < 2 {
		t.Fatalf("expected progress emit before complete, only got: %v", names)
	}
	if names[len(names)-2] != "unlock:progress" {
		t.Errorf("event before complete = %q, want unlock:progress", names[len(names)-2])
	}

	payload := fake.lastPayload()
	if payload["filesDone"] != int64(5) {
		t.Errorf("final filesDone = %v, want 5", payload["filesDone"])
	}
	if payload["bytesDone"] != int64(500) {
		t.Errorf("final bytesDone = %v, want 500", payload["bytesDone"])
	}
}

// TestProgressEmitter_DoneIdempotent: calling Done twice doesn't
// double-emit the complete event. Workers can race the deferred Done
// in the production code, and we'd rather absorb the second call than
// have the frontend dismiss-then-redismiss.
func TestProgressEmitter_DoneIdempotent(t *testing.T) {
	fake := &fakeEmitter{}
	p := newProgressEmitterFromEmitter(fake, "lock", 1, 10)
	p.Done()
	p.Done()

	complete := 0
	for _, n := range fake.names() {
		if n == "lock:complete" {
			complete++
		}
	}
	if complete != 1 {
		t.Errorf("complete events = %d, want 1", complete)
	}
}

// TestProgressEmitter_Throttle: rapid FileDone calls coalesce —
// far fewer events emit than FileDone calls. Throttle is 100ms so
// 50 calls in <1ms should produce ≤2 events plus the (forced) Done.
func TestProgressEmitter_Throttle(t *testing.T) {
	fake := &fakeEmitter{}
	p := newProgressEmitterFromEmitter(fake, "lock", 50, 500)

	for i := 0; i < 50; i++ {
		p.FileDone(10)
	}

	progressEvents := 0
	for _, n := range fake.names() {
		if n == "lock:progress" {
			progressEvents++
		}
	}
	if progressEvents > 5 {
		t.Errorf("progress events = %d, expected throttled (<= 5)", progressEvents)
	}
}

// TestProgressEmitter_NilSafe: every method has to tolerate a nil
// receiver (callers use `defer progress.Done()` even when below the
// size threshold returns nil).
func TestProgressEmitter_NilSafe(t *testing.T) {
	var p *progressEmitter
	// Must not panic.
	p.EmitStart()
	p.FileDone(1)
	p.Done()
	if p.Func() != nil {
		t.Error("nil emitter Func() should return nil")
	}
}

// TestProgressEmitter_FuncBindsToEmitter: the ProgressFunc returned
// by Func() routes back to the same counters.
func TestProgressEmitter_FuncBindsToEmitter(t *testing.T) {
	p := newProgressEmitterFromEmitter(nil, "lock", 3, 30)
	fn := p.Func()
	if fn == nil {
		t.Fatal("Func() returned nil for non-nil emitter")
	}
	fn(7)
	fn(8)
	fn(15)
	if got := p.doneFiles.Load(); got != 3 {
		t.Errorf("doneFiles = %d, want 3", got)
	}
	if got := p.doneBytes.Load(); got != 30 {
		t.Errorf("doneBytes = %d, want 30", got)
	}
}

// TestProgressEmitter_EmitStart: the initial event lets the frontend
// mount its overlay before any worker has reported. Verify it fires
// before any FileDone calls and carries 0/total numbers.
func TestProgressEmitter_EmitStart(t *testing.T) {
	fake := &fakeEmitter{}
	p := newProgressEmitterFromEmitter(fake, "unlock", 10, 1000)
	p.EmitStart()

	if names := fake.names(); len(names) != 1 || names[0] != "unlock:progress" {
		t.Fatalf("after EmitStart, events = %v, want [unlock:progress]", names)
	}
	payload := fake.lastPayload()
	if payload["filesDone"] != int64(0) {
		t.Errorf("EmitStart filesDone = %v, want 0", payload["filesDone"])
	}
	if payload["filesTotal"] != int64(10) {
		t.Errorf("EmitStart filesTotal = %v, want 10", payload["filesTotal"])
	}
}

// TestProgressEmitter_NilWindowSilent: emitter with nil window
// counts but never panics when emit is attempted.
func TestProgressEmitter_NilWindowSilent(t *testing.T) {
	p := newProgressEmitter(nil, "lock", 1, 10)
	p.EmitStart()
	p.FileDone(10)
	p.Done()
	if got := p.doneFiles.Load(); got != 1 {
		t.Errorf("doneFiles = %d, want 1", got)
	}
}

// TestProgressEmitter_ConcurrentFileDone: 1000 workers calling
// FileDone simultaneously while throttle ticks must not lose updates
// or race-detect (run with -race).
func TestProgressEmitter_ConcurrentFileDone(t *testing.T) {
	fake := &fakeEmitter{}
	p := newProgressEmitterFromEmitter(fake, "lock", 1000, 1000)

	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.FileDone(1)
		}()
	}
	wg.Wait()
	p.Done()

	if got := p.doneFiles.Load(); got != 1000 {
		t.Errorf("doneFiles = %d, want 1000", got)
	}
	// Final emit always carries the true total regardless of throttle.
	payload := fake.lastPayload()
	if payload == nil {
		t.Fatal("expected at least one progress payload")
	}
	if payload["filesDone"] != int64(1000) {
		t.Errorf("final filesDone = %v, want 1000", payload["filesDone"])
	}
}

// TestLockTotals_FolderUnlocked: lockTotals reads directory size
// for an unlocked folder vault.
func TestLockTotals_FolderUnlocked(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0600)         // 5
	_ = os.WriteFile(filepath.Join(dir, "b.txt"), []byte("world world"), 0600)   // 11

	files, bytes := lockTotals(monban.VaultEntry{Path: dir})
	if files != 2 {
		t.Errorf("files = %d, want 2", files)
	}
	if bytes != 16 {
		t.Errorf("bytes = %d, want 16", bytes)
	}
}

// TestLockTotals_FolderAlreadyLocked: locked folders aren't relocked,
// so totals should be zero (no progress overlay).
func TestLockTotals_FolderAlreadyLocked(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi"), 0600)
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x42
	}
	if err := monban.LockFolder(key, dir, nil); err != nil {
		t.Fatal(err)
	}

	files, bytes := lockTotals(monban.VaultEntry{Path: dir})
	if files != 0 || bytes != 0 {
		t.Errorf("locked vault should report (0, 0), got (%d, %d)", files, bytes)
	}
}

// TestLockTotals_FileVault: single-file vault returns 1/size when
// unlocked, (0,0) when already locked.
func TestLockTotals_FileVault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	_ = os.WriteFile(path, []byte("01234567"), 0600) // 8

	v := monban.VaultEntry{Path: path, Type: "file"}
	files, bytes := lockTotals(v)
	if files != 1 || bytes != 8 {
		t.Errorf("file vault unlocked totals = (%d, %d), want (1, 8)", files, bytes)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x42
	}
	if err := monban.LockFile(key, path, nil); err != nil {
		t.Fatal(err)
	}
	files, bytes = lockTotals(v)
	if files != 0 || bytes != 0 {
		t.Errorf("locked file vault totals = (%d, %d), want (0, 0)", files, bytes)
	}
}

// TestUnlockTotals_FolderLocked: reads the encrypted manifest of a
// locked folder vault and reports plaintext size.
func TestUnlockTotals_FolderLocked(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("12345"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "b.txt"), []byte("6789"), 0600)
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x42
	}
	if err := monban.LockFolder(key, dir, nil); err != nil {
		t.Fatal(err)
	}

	files, bytes := unlockTotals(key, monban.VaultEntry{Path: dir})
	if files != 2 {
		t.Errorf("files = %d, want 2", files)
	}
	if bytes != 9 {
		t.Errorf("bytes = %d, want 9", bytes)
	}
}

// TestUnlockTotals_FolderUnlocked: an unlocked vault has no manifest
// to read, returns (0, 0).
func TestUnlockTotals_FolderUnlocked(t *testing.T) {
	dir := t.TempDir()
	files, bytes := unlockTotals(nil, monban.VaultEntry{Path: dir})
	if files != 0 || bytes != 0 {
		t.Errorf("unlocked vault should report (0, 0), got (%d, %d)", files, bytes)
	}
}

// TestProgressThreshold: just pin the threshold so a future change
// is intentional (the user picked 500 MB; bumping it silently would
// hide progress on vaults they expect to see it for).
func TestProgressThreshold(t *testing.T) {
	if progressThresholdBytes != 500*1024*1024 {
		t.Errorf("progressThresholdBytes = %d, want 500 MB", progressThresholdBytes)
	}
}

// TestMaybeProgressForLock_BelowThreshold: small vault returns nil.
// Progress emitter is nil so the AdminPanel callsite passes nil
// progress through the rest of the lock path.
func TestMaybeProgressForLock_BelowThreshold(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a"), []byte("tiny"), 0600)

	a := NewApp()
	p := a.maybeProgressForLock(monban.VaultEntry{Path: dir})
	if p != nil {
		t.Errorf("expected nil emitter for below-threshold vault, got %+v", p)
	}
}

// TestMaybeProgressForLock_FileVault_BelowThreshold: a single small
// file is also below the 500 MB threshold.
func TestMaybeProgressForLock_FileVault_BelowThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	_ = os.WriteFile(path, []byte("hello"), 0600)

	a := NewApp()
	p := a.maybeProgressForLock(monban.VaultEntry{Path: path, Type: "file"})
	if p != nil {
		t.Error("expected nil emitter for small file vault")
	}
}

// TestMaybeProgressForUnlock_BelowThreshold: a small locked vault's
// manifest reports below 500 MB → no emitter.
func TestMaybeProgressForUnlock_BelowThreshold(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("tiny"), 0600)
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x42
	}
	if err := monban.LockFolder(key, dir, nil); err != nil {
		t.Fatal(err)
	}

	a := NewApp()
	p := a.maybeProgressForUnlock(key, monban.VaultEntry{Path: dir})
	if p != nil {
		t.Error("expected nil emitter for below-threshold locked vault")
	}
}

// TestMaybeProgressForUnlock_AlreadyUnlocked: a vault that isn't
// locked has no manifest to consult; helper falls through to (0, 0)
// totals and returns nil.
func TestMaybeProgressForUnlock_AlreadyUnlocked(t *testing.T) {
	dir := t.TempDir()
	a := NewApp()
	p := a.maybeProgressForUnlock(nil, monban.VaultEntry{Path: dir})
	if p != nil {
		t.Error("expected nil emitter for already-unlocked vault")
	}
}

// TestProgressEmitter_FileDoneAfterDone: late callbacks (workers
// returning late) must not push more events to the frontend once
// Done has fired. The frontend dismisses the overlay on :complete
// and a stray emit would re-show it briefly. Counters are allowed
// to keep updating — they're harmless and removing the check would
// add a hot-path branch.
func TestProgressEmitter_FileDoneAfterDone(t *testing.T) {
	fake := &fakeEmitter{}
	p := newProgressEmitterFromEmitter(fake, "lock", 2, 20)
	p.FileDone(10)
	p.Done()

	beforeStray := len(fake.events)
	// Force the throttle window to elapse so a late call would
	// otherwise be eligible to emit.
	time.Sleep(emitInterval + 10*time.Millisecond)
	p.FileDone(10)

	if got := len(fake.events); got != beforeStray {
		t.Errorf("FileDone after Done emitted %d stray event(s)", got-beforeStray)
	}
	if got := p.doneFiles.Load(); got != 2 {
		t.Errorf("doneFiles = %d, want 2 (counter still updates after Done)", got)
	}
}
