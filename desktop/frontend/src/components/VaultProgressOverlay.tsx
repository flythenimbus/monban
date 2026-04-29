import { Events } from "@wailsio/runtime";
import { useEffect, useRef, useState } from "react";
import { Lock } from "./icons/Lock";

interface ProgressPayload {
	filesDone: number;
	filesTotal: number;
	bytesDone: number;
	bytesTotal: number;
}

type Mode = "lock" | "unlock";

interface ActiveProgress extends ProgressPayload {
	mode: Mode;
}

/**
 * VaultProgressOverlay listens for "lock:progress" / "unlock:progress"
 * events during multi-vault encryption/decryption, plus the explicit
 * "lock:complete" / "unlock:complete" signal emitted from the backend's
 * deferred Done(). The complete event is what dismisses the overlay —
 * relying on filesDone==filesTotal alone races with view transitions
 * (LockScreen has its own 500ms success delay before swapping to admin)
 * and can produce a flicker where the user sees bar → auth screen →
 * bar → admin instead of bar → admin.
 *
 * Once a complete event arrives we ignore further progress events for
 * the same operation; the next operation will start a fresh cycle when
 * its first progress event lands.
 */
export function VaultProgressOverlay() {
	const [progress, setProgress] = useState<ActiveProgress | null>(null);
	// dismissing is read synchronously from event handlers so we use
	// a ref. A late progress event (delivered after :complete fired)
	// must not re-show the overlay during its 250ms hide animation.
	const dismissingRef = useRef(false);
	const [dismissTick, setDismissTick] = useState(0);

	useEffect(() => {
		const handleProgress =
			(mode: Mode) =>
			({ data }: { data: ProgressPayload }) => {
				// A filesDone==0 event is the EmitStart of a new
				// operation. Clear any leftover dismissing state from
				// the previous run so back-to-back lock-then-unlock
				// (or vice versa) renders correctly.
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
		// Brief visual hold so the user sees 100% before the bar
		// disappears. We do NOT clear dismissingRef on the timer:
		// stale progress events from the just-completed run could
		// still arrive after this timer fires (Wails IPC ordering
		// vs JS scheduling). Dismissing stays true until the next
		// fresh-start event (filesDone==0) clears it.
		const t = window.setTimeout(() => setProgress(null), 250);
		return () => window.clearTimeout(t);
	}, [dismissTick]);

	if (!progress || progress.filesTotal === 0) return null;

	const pct = Math.min(
		100,
		Math.round((progress.bytesDone / Math.max(1, progress.bytesTotal)) * 100),
	);
	const verb = progress.mode === "lock" ? "Encrypting" : "Decrypting";

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-md p-6">
			<div className="glass rounded-2xl max-w-sm w-full p-6">
				<div className="flex justify-center mb-5">
					<div className="relative">
						<div className="absolute inset-0 rounded-full bg-accent/20 animate-ping motion-reduce:animate-none" />
						<div className="relative w-14 h-14 rounded-full bg-accent/15 text-accent flex items-center justify-center [&_svg]:size-6">
							<Lock />
						</div>
					</div>
				</div>
				<h2 className="text-base font-semibold text-text text-center mb-1">
					{verb} vaults
				</h2>
				<p className="text-xs text-text-secondary text-center mb-4">
					{progress.filesDone.toLocaleString()} /{" "}
					{progress.filesTotal.toLocaleString()} files ·{" "}
					{formatBytes(progress.bytesDone)} / {formatBytes(progress.bytesTotal)}
				</p>
				<div className="h-2 w-full rounded-full bg-black/10 dark:bg-white/10 overflow-hidden">
					<div
						className="h-full bg-accent transition-[width] duration-150 ease-out"
						style={{ width: `${pct}%` }}
					/>
				</div>
				<p className="mt-3 text-center text-xs text-text-secondary tabular-nums">
					{pct}%
				</p>
			</div>
		</div>
	);
}

function formatBytes(b: number): string {
	if (b < 1024) return `${b} B`;
	const units = ["KB", "MB", "GB", "TB"];
	let v = b / 1024;
	let i = 0;
	while (v >= 1024 && i < units.length - 1) {
		v /= 1024;
		i++;
	}
	return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}
