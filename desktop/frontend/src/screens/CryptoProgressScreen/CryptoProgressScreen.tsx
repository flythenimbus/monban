import { useAutoResize } from "../../hooks/useAutoResize";
import type { ActiveProgress } from "../../hooks/useVaultProgress";

interface Props {
	progress: ActiveProgress;
}

export function CryptoProgressScreen({ progress }: Props) {
	const contentRef = useAutoResize();

	const pct = Math.min(
		100,
		Math.round((progress.bytesDone / Math.max(1, progress.bytesTotal)) * 100),
	);
	const verb = progress.mode === "lock" ? "Encrypting" : "Decrypting";

	return (
		<div
			ref={contentRef}
			className="gradient-bg flex flex-col gap-4 p-8 pt-14 select-none"
			style={{ WebkitAppRegion: "drag" } as React.CSSProperties}
		>
			<div
				className="flex flex-col gap-4"
				style={{ WebkitAppRegion: "no-drag" } as React.CSSProperties}
			>
				<div className="text-center">
					<h1 className="text-lg font-semibold text-text">{verb} vaults</h1>
					<p aria-live="polite" className="text-text-secondary text-sm mt-1">
						{progress.filesDone.toLocaleString()} /{" "}
						{progress.filesTotal.toLocaleString()} files ·{" "}
						{formatBytes(progress.bytesDone)} /{" "}
						{formatBytes(progress.bytesTotal)}
					</p>
				</div>

				<div className="h-2 w-full rounded-full bg-black/10 dark:bg-white/10 overflow-hidden">
					<div
						className="h-full bg-accent transition-[width] duration-150 ease-out"
						style={{ width: `${pct}%` }}
					/>
				</div>

				<p className="text-center text-xs text-text-secondary tabular-nums">
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
