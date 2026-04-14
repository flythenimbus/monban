import { useState } from "react";
import { api } from "../../../api";
import { Input, PinAuth } from "../../../components";
import { friendlyError } from "../../../util/errors";
import { useAdmin } from "../AdminContext";

export function KeysTab() {
	const { keys, setError: onError, refresh: onRefresh } = useAdmin();
	const [showAdd, setShowAdd] = useState(false);
	const [pin, setPin] = useState("");
	const [label, setLabel] = useState("");
	const [adding, setAdding] = useState(false);
	const [removingCredId, setRemovingCredId] = useState<string | null>(null);

	const handleAdd = async () => {
		if (!pin || !label) return;
		setAdding(true);
		try {
			await api.register(pin, label);
			setShowAdd(false);
			setPin("");
			setLabel("");
			await onRefresh();
		} catch (err: unknown) {
			onError(friendlyError(err));
		} finally {
			setAdding(false);
		}
	};

	const handleRemove = (credId: string) => {
		setRemovingCredId(credId);
	};

	const handleRemoveWithPin = async (removePin: string) => {
		if (!removingCredId) return;
		try {
			await api.removeKey(removingCredId, removePin);
			setRemovingCredId(null);
			await onRefresh();
		} catch (err: unknown) {
			onError(friendlyError(err));
			setRemovingCredId(null);
		}
	};

	return (
		<div className="space-y-3 flex-1">
			<div className="rounded-xl px-4 py-3 text-xs leading-relaxed bg-amber-500/10 text-amber-600 dark:text-amber-400">
				<p>
					Back up your security config. Without it, encrypted files are
					unrecoverable.
				</p>
				<button
					type="button"
					onClick={() => api.revealSecureConfig()}
					className="mt-2 underline hover:opacity-80 transition-opacity cursor-pointer"
				>
					Show config file
				</button>
			</div>
			{keys.map((k) => (
				<div key={k.credential_id} className="space-y-0">
					<div className="glass rounded-xl px-4 py-3 flex items-center justify-between">
						<span className="text-sm font-medium text-text">{k.label}</span>
						<button
							type="button"
							onClick={() => handleRemove(k.credential_id)}
							disabled={keys.length <= 1 || removingCredId !== null}
							aria-label={`Remove ${k.label}`}
							className="text-xs text-text-secondary hover:text-error transition-colors disabled:opacity-30"
						>
							Remove
						</button>
					</div>
					{removingCredId === k.credential_id && (
						<PinAuth
							label={`Authenticate to remove "${k.label}"`}
							onSubmit={handleRemoveWithPin}
							onCancel={() => setRemovingCredId(null)}
						/>
					)}
				</div>
			))}

			{showAdd ? (
				<div className="glass rounded-xl p-4 space-y-3">
					<Input
						type="text"
						label="Key label"
						placeholder="Key label"
						value={label}
						onChange={(e) => setLabel(e.target.value)}
					/>
					<Input
						type="password"
						label="Security key PIN"
						placeholder="Security key PIN"
						value={pin}
						onChange={(e) => setPin(e.target.value)}
					/>
					<div className="flex gap-2">
						<button
							type="button"
							onClick={handleAdd}
							disabled={!pin || !label || adding}
							className="btn-primary"
						>
							{adding ? "Registering..." : "Register Key"}
						</button>
						<button
							type="button"
							onClick={() => {
								setShowAdd(false);
								setPin("");
								setLabel("");
							}}
							className="btn-secondary"
						>
							Cancel
						</button>
					</div>
				</div>
			) : (
				<button
					type="button"
					onClick={() => setShowAdd(true)}
					className="text-sm text-accent hover:opacity-80 transition-opacity"
				>
					+ Add Key
				</button>
			)}
		</div>
	);
}
