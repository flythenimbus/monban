package app

import (
	"sync"
	"sync/atomic"
	"time"

	"monban/internal/monban"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// windowEmitter is the subset of *application.WebviewWindow that
// progressEmitter actually uses. Defined here so unit tests can
// substitute a recording fake; the real Wails window satisfies it
// implicitly. Keep the surface tiny — every method added here has
// to be reimplemented in tests.
type windowEmitter interface {
	EmitEvent(name string, data ...any) bool
}

// --- Types ---

// progressEmitter is the bridge between the worker-side ProgressFunc
// callback and the Wails event channel. Workers call FileDone(bytes)
// once per processed file; the emitter throttles per-event work and
// forwards a snapshot to the frontend on the named Wails event.
//
// Throttling is mandatory: a 5GB / 50K-file vault would otherwise emit
// 50K events in a few seconds, which both spams the IPC channel and
// makes React rerender for every file. We coalesce to one event per
// emitInterval, plus an unconditional final emit on Done() and a
// separate <op>:complete event so the frontend has an unambiguous
// "operation finished" signal that doesn't race with view transitions.
type progressEmitter struct {
	window windowEmitter
	op     string // base name, e.g. "lock" or "unlock"

	totalFiles int64
	totalBytes int64

	doneFiles atomic.Int64
	doneBytes atomic.Int64

	mu       sync.Mutex
	lastEmit time.Time
	closed   bool
}

// --- Constants ---

// emitInterval bounds Wails event frequency during a lock/unlock run.
// Frontend renders smoothly at this rate without IPC contention.
const emitInterval = 100 * time.Millisecond

// progressThresholdBytes is the minimum vault size before an on-demand
// lock/unlock from the AdminPanel surfaces the progress overlay. Small
// vaults finish in well under the overlay's render-and-dismiss window
// and would just produce a flicker. The bulk Lock()/Unlock() (full app
// lock on key removal or app start) always emit progress regardless of
// size — the user is already at the lock screen and expects feedback.
const progressThresholdBytes int64 = 500 * 1024 * 1024 // 500 MB

// --- Public functions ---

// maybeProgressForLock returns a started emitter for an on-demand lock
// of v if the vault's plaintext exceeds progressThresholdBytes, else nil.
// progressEmitter methods are nil-safe so callers can use the result
// directly with defer .Done() and .Func().
func (a *App) maybeProgressForLock(v monban.VaultEntry) *progressEmitter {
	files, bytes := lockTotals(v)
	if bytes < progressThresholdBytes {
		return nil
	}
	p := newProgressEmitter(a.window, "lock", files, bytes)
	p.EmitStart()
	return p
}

// maybeProgressForUnlock returns a started emitter for an on-demand
// unlock of v if the vault's plaintext exceeds progressThresholdBytes,
// else nil. key must be the key the vault was locked with so the
// manifest can be read for totals.
func (a *App) maybeProgressForUnlock(key []byte, v monban.VaultEntry) *progressEmitter {
	files, bytes := unlockTotals(key, v)
	if bytes < progressThresholdBytes {
		return nil
	}
	p := newProgressEmitter(a.window, "unlock", files, bytes)
	p.EmitStart()
	return p
}

// lockTotals returns file count and plaintext bytes for an unlocked
// vault entry, used to gate the AdminPanel lock-button progress overlay.
// Returns zeros (no progress) for entries that aren't currently
// lockable — i.e. already locked, missing, or unreadable.
func lockTotals(v monban.VaultEntry) (files, bytes int64) {
	f, b, _ := monban.VaultFor(v).PlaintextStats()
	return f, b
}

// unlockTotals returns file count and plaintext bytes for a locked
// vault entry, read from its encrypted manifest. Returns zeros if the
// vault is already unlocked or the manifest can't be read.
func unlockTotals(key []byte, v monban.VaultEntry) (files, bytes int64) {
	f, b, _ := monban.VaultFor(v).LockedStats(key)
	return f, b
}

// newProgressEmitter creates a progressEmitter for one lock/unlock run.
// op is the operation base name ("lock" or "unlock"); progress events
// are sent on "<op>:progress" and a final completion event is sent on
// "<op>:complete". A nil *application.WebviewWindow is normalised to
// a nil interface so emit becomes a no-op (the app is constructed
// before SetWindow, and tests usually skip the window entirely).
func newProgressEmitter(w *application.WebviewWindow, op string, totalFiles, totalBytes int64) *progressEmitter {
	var emitter windowEmitter
	if w != nil {
		emitter = w
	}
	return &progressEmitter{
		window:     emitter,
		op:         op,
		totalFiles: totalFiles,
		totalBytes: totalBytes,
	}
}

// newProgressEmitterFromEmitter is the test-only constructor that
// accepts a windowEmitter directly so tests can inject a fake. Public
// callers go through newProgressEmitter, which keeps the production
// signature pinned to the concrete Wails window type.
func newProgressEmitterFromEmitter(emitter windowEmitter, op string, totalFiles, totalBytes int64) *progressEmitter {
	return &progressEmitter{
		window:     emitter,
		op:         op,
		totalFiles: totalFiles,
		totalBytes: totalBytes,
	}
}

// FileDone increments the done counters and emits if the throttle
// window has elapsed. Safe for concurrent calls from worker pool
// goroutines, and tolerant of a nil receiver — Func() returns nil
// for a nil emitter so this is normally guarded at the call site,
// but defensive nil-handling keeps direct callers (and tests) safe.
func (p *progressEmitter) FileDone(bytes int64) {
	if p == nil {
		return
	}
	p.doneFiles.Add(1)
	p.doneBytes.Add(bytes)
	p.maybeEmit(false)
}

// Func returns a monban.ProgressFunc bound to this emitter, suitable
// for passing into Vault.Lock / Vault.Unlock. Returns nil if the
// emitter itself is nil so callers can pre-emptively short-circuit
// when no window is attached.
func (p *progressEmitter) Func() monban.ProgressFunc {
	if p == nil {
		return nil
	}
	return func(bytes int64) { p.FileDone(bytes) }
}

// EmitStart sends an immediate event so the frontend can mount the
// progress overlay before any file work has happened. Used to
// distinguish "lock about to begin, big vault, expect a wait" from
// "lock complete instantly, no overlay needed".
func (p *progressEmitter) EmitStart() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.emitLocked()
}

// Done forces a final progress emit and then sends a separate
// "<op>:complete" event. The complete event is the unambiguous
// "operation finished" signal — relying on filesDone==filesTotal
// in the progress event alone races with view transitions on the
// frontend and can produce a bar/auth-screen/bar flicker before
// the admin view stabilises. Idempotent.
func (p *progressEmitter) Done() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	p.emitLocked()
	if p.window != nil {
		p.window.EmitEvent(p.op + ":complete")
	}
}

// --- Private methods ---

func (p *progressEmitter) maybeEmit(force bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Once Done has fired we've already emitted the final progress
	// + complete events. Late FileDone calls (a worker that finished
	// after parallelOp returned but whose goroutine wasn't scheduled
	// in time) must not push more events: the frontend dismissed
	// the overlay on :complete and a stray emit would re-show it.
	if p.closed {
		return
	}
	if !force && time.Since(p.lastEmit) < emitInterval {
		return
	}
	p.emitLocked()
}

func (p *progressEmitter) emitLocked() {
	p.lastEmit = time.Now()
	if p.window == nil {
		return
	}
	p.window.EmitEvent(p.op+":progress", map[string]any{
		"filesDone":  p.doneFiles.Load(),
		"filesTotal": p.totalFiles,
		"bytesDone":  p.doneBytes.Load(),
		"bytesTotal": p.totalBytes,
	})
}
