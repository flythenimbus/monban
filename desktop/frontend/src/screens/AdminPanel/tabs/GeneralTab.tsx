import { Clipboard, Dialogs } from "@wailsio/runtime";
import { useState } from "react";
import { api } from "../../../api";
import { Button, Input, PinAuth, Select, Toggle } from "../../../components";
import { Folder } from "../../../components/icons/Folder";
import type { SudoGateMode } from "../../../types";
import { friendlyError } from "../../../util/errors";
import { useAdmin } from "../AdminContext";
import { VaultRow } from "./VaultRow";

export function GeneralTab() {
	const {
		settings,
		handleToggle: onToggle,
		handleSetting: onSetting,
		pendingChange,
		confirmPendingChange,
		cancelPendingChange,
		vaults,
		setError: onError,
		refresh: onRefresh,
	} = useAdmin();
	const [inputPath, setInputPath] = useState("");
	const [addPending, setAddPending] = useState(false);
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

	const handleBrowse = async () => {
		const selected = await Dialogs.OpenFile({
			CanChooseFiles: true,
			CanChooseDirectories: true,
			Title: "Select a file or folder",
		});
		if (selected) setInputPath(selected as string);
	};

	const handleAdd = () => {
		if (!inputPath) return;
		setAddPending(true);
	};

	const handleAddWithPin = async (pin: string) => {
		onError("");
		try {
			await api.addPath(inputPath, pin);
			setInputPath("");
			setAddPending(false);
			await onRefresh();
		} catch (err: unknown) {
			onError(friendlyError(err));
			setAddPending(false);
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
						disabled={!!pendingChange}
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
						disabled={!!pendingChange}
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
						disabled={!!pendingChange}
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
				{pendingChange && (
					<PinAuth
						onSubmit={confirmPendingChange}
						onCancel={cancelPendingChange}
					/>
				)}
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
							<VaultRow key={v.path} vault={v} onRefresh={onRefresh} />
						))}
					</div>
				)}

				<div className="flex gap-2 mt-3">
					<div className="relative flex-1">
						<Input
							type="text"
							label="Path"
							placeholder="Folder or file path"
							value={inputPath}
							onChange={(e) => setInputPath(e.target.value)}
							onKeyDown={(e) => e.key === "Enter" && handleAdd()}
							className="w-full"
							style={{ paddingRight: "2.5rem" }}
						/>
						<button
							type="button"
							onClick={handleBrowse}
							className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-text-secondary/50 hover:text-text-secondary transition-colors cursor-pointer"
							aria-label="Browse for file or folder"
						>
							<Folder />
						</button>
					</div>
					<Button
						onClick={handleAdd}
						disabled={!inputPath || addPending}
						fullWidth={false}
						className="px-5"
					>
						Add
					</Button>
				</div>
				{addPending && (
					<PinAuth
						label="Authenticate to add this path"
						onSubmit={handleAddWithPin}
						onCancel={() => setAddPending(false)}
					/>
				)}
			</div>
		</div>
	);
}
