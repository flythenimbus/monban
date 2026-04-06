import { Clipboard } from "@wailsio/runtime";
import { useState } from "react";
import { api } from "../../../api";
import { Input, Select, Toggle } from "../../../components";
import type { SudoGateMode } from "../../../types";
import { friendlyError } from "../../../util/errors";
import { useAdmin } from "../AdminContext";

export function GeneralTab() {
	const {
		settings,
		handleToggle: onToggle,
		handleSetting: onSetting,
		vaults,
		setError: onError,
		refresh: onRefresh,
	} = useAdmin();
	const [inputPath, setInputPath] = useState("");
	const [adding, setAdding] = useState(false);
	const [sudoCmd, setSudoCmd] = useState("");
	const [copied, setCopied] = useState(false);
	const isMac = navigator.platform.startsWith("Mac");

	const handleSudoGate = async (value: SudoGateMode) => {
		onSetting("sudo_gate", value);
		try {
			const cmd = await api.getSudoGateCommand(value);
			setSudoCmd(cmd || "");
		} catch {
			setSudoCmd("");
		}
	};

	const handleAdd = async () => {
		if (!inputPath) return;
		setAdding(true);
		onError("");
		try {
			await api.addPath(inputPath);
			setInputPath("");
			await onRefresh();
		} catch (err: unknown) {
			onError(friendlyError(err));
		} finally {
			setAdding(false);
		}
	};

	const handleRemove = async (vaultPath: string) => {
		try {
			await api.removeFolder(vaultPath);
			await onRefresh();
		} catch (err: unknown) {
			onError(friendlyError(err));
		}
	};

	return (
		<div className="space-y-5">
			<div className="glass rounded-xl divide-y divide-black/5 dark:divide-white/5">
				<div className="flex items-center justify-between px-4 py-3">
					<div>
						<div className="text-sm font-medium text-text">Open on startup</div>
						<div className="text-xs text-text-secondary">
							Launch Monban when you log in
						</div>
					</div>
					<Toggle
						checked={settings.open_on_startup}
						onChange={() => onToggle("open_on_startup")}
						label="Open on startup"
					/>
				</div>
				<div className="flex items-center justify-between px-4 py-3">
					<div>
						<div className="text-sm font-medium text-text">
							Force authentication
						</div>
						<div className="text-xs text-text-secondary">
							Fullscreen lock, can't be dismissed
						</div>
					</div>
					<Toggle
						checked={settings.force_authentication}
						onChange={() => onToggle("force_authentication")}
						label="Force authentication"
					/>
				</div>
				<div className="flex items-center justify-between px-4 py-3">
					<div>
						<div className="text-sm font-medium text-text">Sudo gate</div>
						<div className="text-xs text-text-secondary">
							Require security key for sudo
						</div>
					</div>
					<Select
						label="Sudo gate"
						value={settings.sudo_gate || "off"}
						onChange={(v) => handleSudoGate(v as SudoGateMode)}
						options={[
							{ value: "off", label: "Off" },
							{ value: "default", label: "Default" },
							{
								value: "strict",
								label: isMac ? "Strict" : "Strict (sudo + su)",
							},
						]}
					/>
				</div>
				{sudoCmd && (
					<div className="px-4 py-3">
						<div className="text-xs text-text-secondary mb-2">
							Run in Terminal to apply:
						</div>
						<div className="flex items-center gap-2 bg-black/30 rounded-lg px-3 py-2">
							<code className="text-xs font-mono text-white/90 break-all flex-1">
								{sudoCmd}
							</code>
							<button
								type="button"
								onClick={() => {
									Clipboard.SetText(sudoCmd);
									setCopied(true);
									setTimeout(() => setCopied(false), 2000);
								}}
								className="shrink-0 text-xs text-accent hover:text-accent/80 transition-colors cursor-pointer font-medium"
							>
								{copied ? "Copied" : "Copy"}
							</button>
						</div>
					</div>
				)}
			</div>

			<div>
				<h2 className="text-sm font-medium text-text-secondary mb-3">
					Protected Items
				</h2>
				{vaults.length === 0 ? (
					<div className="glass rounded-xl p-5 text-center">
						<p className="text-text-secondary text-sm">Nothing protected yet</p>
						<p className="text-text-secondary text-xs mt-1">
							Add a folder or file to start encrypting
						</p>
					</div>
				) : (
					<div className="space-y-2">
						{vaults.map((v) => (
							<div
								key={v.path}
								className="glass rounded-xl px-4 py-3 flex items-center justify-between"
							>
								<div>
									<div className="text-sm font-medium text-text">{v.label}</div>
									<div className="text-xs text-text-secondary">{v.path}</div>
								</div>
								<button
									type="button"
									onClick={() => handleRemove(v.path)}
									aria-label={`Remove ${v.label}`}
									className="text-xs text-text-secondary hover:text-error transition-colors cursor-pointer"
								>
									Remove
								</button>
							</div>
						))}
					</div>
				)}

				<div className="flex gap-2 mt-3">
					<Input
						type="text"
						label="Path"
						placeholder="Folder or file path"
						value={inputPath}
						onChange={(e) => setInputPath(e.target.value)}
						onKeyDown={(e) => e.key === "Enter" && handleAdd()}
						className="flex-1"
					/>
					<button
						type="button"
						onClick={handleAdd}
						disabled={!inputPath || adding}
						className="btn-primary w-auto! px-5"
					>
						{adding ? "..." : "Add"}
					</button>
				</div>
			</div>
		</div>
	);
}
