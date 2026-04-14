import { useState } from "react";
import { api } from "../../../api";
import { Alert, Input, Select } from "../../../components";
import { Lock } from "../../../components/icons/Lock";
import { Times } from "../../../components/icons/Times";
import { Trash } from "../../../components/icons/Trash";
import { Unlock } from "../../../components/icons/Unlock";
import type { VaultStatus } from "../../../types";
import { friendlyError } from "../../../util/errors";

type VaultRowState =
	| "idle"
	| "loading"
	| "pin_input"
	| "pin_remove"
	| "waiting_touch"
	| "error";

export function VaultRow({
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
		if (state === "pin_remove") {
			handleRemoveWithPin();
		} else if (pendingMode) {
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

	const handleRemove = () => {
		setPendingMode(null);
		setState("pin_remove");
	};

	const handleRemoveWithPin = async () => {
		setState("waiting_touch");
		setError("");
		try {
			await api.removeFolder(vault.path, pin);
			setPin("");
			await onRefresh();
			setState("idle");
		} catch (err: unknown) {
			setError(friendlyError(err));
			setState("pin_remove");
		}
	};

	return (
		<div className="glass rounded-xl px-4 py-3 space-y-2">
			<div className="flex items-center justify-between">
				<div className="flex-1 min-w-0 mr-3">
					<div className="text-sm font-medium text-text">{vault.label}</div>
					<div
						title={vault.path}
						className="text-xs text-text-secondary truncate"
					>
						{vault.path}
					</div>
				</div>
				<div className="flex items-center gap-3 shrink-0">
					<Select
						label="Decrypt mode"
						value={mode}
						onChange={handleModeChange}
						options={[
							{ value: "eager", label: "Immediate" },
							{ value: "lazy", label: "On demand" },
							{ value: "lazy_strict", label: "Strict" },
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

			{(state === "pin_input" || state === "pin_remove") && (
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
