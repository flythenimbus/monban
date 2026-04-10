import { Clipboard } from "@wailsio/runtime";
import { useState } from "react";
import { api } from "../../../api";
import { Alert, Input, Select, Toggle } from "../../../components";
import { Lock } from "../../../components/icons/Lock";
import { Times } from "../../../components/icons/Times";
import { Trash } from "../../../components/icons/Trash";
import { Unlock } from "../../../components/icons/Unlock";
import type { SudoGateMode, VaultStatus } from "../../../types";
import { friendlyError } from "../../../util/errors";
import { useAdmin } from "../AdminContext";

type VaultRowState =
	| "idle"
	| "loading"
	| "pin_input"
	| "waiting_touch"
	| "error";

function VaultRow({
	vault,
	onRefresh,
}: {
	vault: VaultStatus;
	onRefresh: () => Promise<void>;
}) {
	const [state, setState] = useState<VaultRowState>("idle");
	const [error, setError] = useState("");
	const [pin, setPin] = useState("");
	const [pendingMode, setPendingMode] = useState<string | null>(null);

	const mode = vault.decrypt_mode || "eager";
	const showDecrypt = vault.locked;
	const showLock = !vault.locked;

	const handleDecrypt = async () => {
		if (mode === "lazy_strict") {
			setState("pin_input");
			setPendingMode(null);
			return;
		}

		setState("loading");
		setError("");
		try {
			await api.decryptLazyVault(vault.path, "");
			await onRefresh();
			setState("idle");
		} catch (err: unknown) {
			setError(friendlyError(err));
			setState("error");
		}
	};

	const handleDecryptWithPin = async () => {
		setState("waiting_touch");
		setError("");
		try {
			await api.decryptLazyVault(vault.path, pin);
			setPin("");
			await onRefresh();
			setState("idle");
		} catch (err: unknown) {
			setError(friendlyError(err));
			setState("pin_input");
		}
	};

	const handleModeChange = async (newMode: string) => {
		if (newMode === mode) return;

		const needsPin = mode === "lazy_strict" || newMode === "lazy_strict";

		if (needsPin) {
			setPendingMode(newMode);
			setState("pin_input");
			return;
		}

		setState("loading");
		setError("");
		try {
			await api.updateVaultMode(vault.path, newMode, "");
			await onRefresh();
			setState("idle");
		} catch (err: unknown) {
			setError(friendlyError(err));
			setState("error");
		}
	};

	const handleModeChangeWithPin = async () => {
		if (!pendingMode) return;
		setState("waiting_touch");
		setError("");
		try {
			await api.updateVaultMode(vault.path, pendingMode, pin);
			setPin("");
			setPendingMode(null);
			await onRefresh();
			setState("idle");
		} catch (err: unknown) {
			setError(friendlyError(err));
			setState("pin_input");
		}
	};

	const handlePinSubmit = () => {
		if (pendingMode) {
			handleModeChangeWithPin();
		} else {
			handleDecryptWithPin();
		}
	};

	const handleCancel = () => {
		setState("idle");
		setPin("");
		setPendingMode(null);
		setError("");
	};

	const handleLockVault = async () => {
		setState("loading");
		setError("");
		try {
			await api.lockVault(vault.path);
			await onRefresh();
			setState("idle");
		} catch (err: unknown) {
			setError(friendlyError(err));
			setState("error");
		}
	};

	const handleRemove = async () => {
		try {
			await api.removeFolder(vault.path);
			await onRefresh();
		} catch (err: unknown) {
			setError(friendlyError(err));
			setState("error");
		}
	};

	return (
		<div className="glass rounded-xl px-4 py-3 space-y-2">
			<div className="flex items-center justify-between">
				<div className="flex-1 min-w-0 mr-3">
					<div className="text-sm font-medium text-text">{vault.label}</div>
					<div className="text-xs text-text-secondary truncate">
						{vault.path}
					</div>
				</div>
				<div className="flex items-center gap-3 shrink-0">
					<Select
						label="Decrypt mode"
						value={mode}
						onChange={handleModeChange}
						options={[
							{ value: "eager", label: "Automatic" },
							{ value: "lazy", label: "On demand" },
							{ value: "lazy_strict", label: "On demand (PIN)" },
						]}
					/>
					{showDecrypt &&
						state !== "pin_input" &&
						state !== "waiting_touch" && (
							<button
								type="button"
								onClick={handleDecrypt}
								disabled={state === "loading"}
								aria-label={`Decrypt ${vault.label}`}
								title="Decrypt"
								className="text-text-secondary hover:text-accent transition-colors cursor-pointer [&_svg]:size-4"
							>
								<Unlock />
							</button>
						)}
					{showLock && (
						<button
							type="button"
							onClick={handleLockVault}
							disabled={state === "loading"}
							aria-label={`Re-encrypt ${vault.label}`}
							title="Re-encrypt"
							className="text-text-secondary hover:text-accent transition-colors cursor-pointer [&_svg]:size-4"
						>
							<Lock />
						</button>
					)}
					<button
						type="button"
						onClick={handleRemove}
						aria-label={`Remove ${vault.label}`}
						title="Remove"
						className="text-text-secondary hover:text-error transition-colors cursor-pointer [&_svg]:size-4"
					>
						<Trash />
					</button>
				</div>
			</div>

			{state === "waiting_touch" && (
				<div className="text-xs text-accent animate-pulse">
					Touch your security key...
				</div>
			)}

			{state === "pin_input" && (
				<div className="flex items-center gap-2">
					<Input
						type="password"
						label="PIN"
						placeholder="Security key PIN"
						value={pin}
						onChange={(e) => setPin(e.target.value)}
						onKeyDown={(e) => e.key === "Enter" && pin && handlePinSubmit()}
						className="flex-1 !py-1.5 !px-2.5 !text-xs"
					/>
					<button
						type="button"
						onClick={handlePinSubmit}
						disabled={!pin}
						className="btn-primary w-auto! px-2.5 py-1.5 text-xs !text-xs !rounded-md"
					>
						Authenticate
					</button>
					<button
						type="button"
						onClick={handleCancel}
						aria-label="Cancel"
						className="text-text-secondary hover:text-text transition-colors cursor-pointer [&_svg]:size-4"
					>
						<Times />
					</button>
				</div>
			)}

			{error && (
				<Alert
					onDismiss={() => {
						setError("");
						if (state === "error") setState("idle");
					}}
				>
					{error}
				</Alert>
			)}
		</div>
	);
}

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
							<VaultRow key={v.path} vault={v} onRefresh={onRefresh} />
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
