import { Browser } from "@wailsio/runtime";
import { useEffect, useState } from "react";
import { api } from "../../../api";
import type { UpdateInfo } from "../../../types";
import { friendlyError } from "../../../util/errors";

export function UpdateAlert({ onError }: { onError: (msg: string) => void }) {
	const [version, setVersion] = useState("");
	const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
	const [checking, setChecking] = useState(false);

	useEffect(() => {
		api.getVersion().then(setVersion).catch(() => {});
		api.checkForUpdate().then(setUpdateInfo).catch(() => {});
	}, []);

	const handleCheckUpdate = async () => {
		setChecking(true);
		setUpdateInfo(null);
		try {
			const info = await api.checkForUpdate();
			setUpdateInfo(info);
		} catch (err: unknown) {
			onError(friendlyError(err));
		} finally {
			setChecking(false);
		}
	};

	return (
		<div>
			<h2 className="text-sm font-medium text-text-secondary mb-3">About</h2>
			<div className="glass rounded-xl px-4 py-3">
				<div className="flex items-center justify-between">
					<div>
						<div className="text-sm font-medium text-text">
							Monban {version && `v${version}`}
						</div>
						{updateInfo?.update_available && (
							<div className="text-xs text-accent mt-0.5">
								v{updateInfo.latest_version} available
							</div>
						)}
						{updateInfo && !updateInfo.update_available && (
							<div className="text-xs text-text-secondary mt-0.5">
								You're up to date
							</div>
						)}
					</div>
					<button
						type="button"
						onClick={
							updateInfo?.update_available
								? () => Browser.OpenURL(updateInfo.release_url)
								: handleCheckUpdate
						}
						disabled={checking}
						className="text-xs text-accent hover:text-accent/80 transition-colors cursor-pointer font-medium"
					>
						{checking
							? "Checking..."
							: updateInfo?.update_available
								? "Download"
								: "Check for updates"}
					</button>
				</div>
			</div>
		</div>
	);
}
