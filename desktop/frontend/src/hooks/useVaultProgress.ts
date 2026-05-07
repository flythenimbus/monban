import { Events } from "@wailsio/runtime";
import { useEffect, useRef, useState } from "react";

interface ProgressPayload {
	filesDone: number;
	filesTotal: number;
	bytesDone: number;
	bytesTotal: number;
}

type Mode = "lock" | "unlock";

export interface ActiveProgress extends ProgressPayload {
	mode: Mode;
}

/**
 * Listens for "lock:progress" / "unlock:progress" events during
 * multi-vault encryption/decryption, plus the explicit "lock:complete"
 * / "unlock:complete" signal emitted from the backend's deferred Done().
 * The complete event is what dismisses the screen — relying on
 * filesDone==filesTotal alone races with view transitions (LockScreen
 * has its own 500ms success delay before swapping to admin) and can
 * produce a flicker.
 *
 * Once a complete event arrives we ignore further progress events for
 * the same operation; the next operation starts a fresh cycle when its
 * first progress event lands.
 */
export function useVaultProgress(): ActiveProgress | null {
	const [progress, setProgress] = useState<ActiveProgress | null>(null);
	// dismissing is read synchronously from event handlers so we use
	// a ref. A late progress event (delivered after :complete fired)
	// must not re-show the screen during its 250ms hide delay.
	const dismissingRef = useRef(false);
	const [dismissTick, setDismissTick] = useState(0);

	useEffect(() => {
		const handleProgress =
			(mode: Mode) =>
			({ data }: { data: ProgressPayload }) => {
				// A filesDone==0 event is the EmitStart of a new operation.
				// Clear leftover dismissing state from the previous run so
				// back-to-back lock-then-unlock renders correctly.
				if (data.filesDone === 0) {
					dismissingRef.current = false;
				}
				if (dismissingRef.current) return;
				setProgress({ ...data, mode });
			};

		const handleComplete = () => {
			dismissingRef.current = true;
			setDismissTick((n) => n + 1);
		};

		const offLockProgress = Events.On("lock:progress", handleProgress("lock"));
		const offUnlockProgress = Events.On(
			"unlock:progress",
			handleProgress("unlock"),
		);
		const offLockComplete = Events.On("lock:complete", handleComplete);
		const offUnlockComplete = Events.On("unlock:complete", handleComplete);

		return () => {
			offLockProgress();
			offUnlockProgress();
			offLockComplete();
			offUnlockComplete();
		};
	}, []);

	useEffect(() => {
		if (dismissTick === 0) return;
		// Brief visual hold so the user sees 100% before the screen
		// disappears. We do NOT clear dismissingRef on the timer:
		// stale progress events could still arrive after this fires
		// (Wails IPC ordering vs JS scheduling). Dismissing stays true
		// until the next fresh-start event (filesDone==0) clears it.
		const t = window.setTimeout(() => setProgress(null), 250);
		return () => window.clearTimeout(t);
	}, [dismissTick]);

	if (!progress || progress.filesTotal === 0) return null;
	return progress;
}
