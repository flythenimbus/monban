import type { ReactNode } from "react";
import {
	createContext,
	useCallback,
	useContext,
	useEffect,
	useState,
} from "react";
import { api } from "../../api";
import type { KeyInfo, Settings, VaultStatus } from "../../types";
import { friendlyError } from "../../util/errors";

// Settings that require FIDO2 re-auth (PIN + touch) to change.
// All settings require FIDO2 re-auth — they're in the HMAC-signed config.
const secureSettingKeys: Set<keyof Settings> = new Set([
	"open_on_startup",
	"force_authentication",
	"admin_gate",
]);

interface PendingSettingsChange {
	updated: Settings;
	previous: Settings;
}

interface AdminContextValue {
	vaults: VaultStatus[];
	keys: KeyInfo[];
	settings: Settings;
	error: string;
	pendingChange: PendingSettingsChange | null;
	refresh: () => Promise<void>;
	setError: (msg: string) => void;
	handleToggle: (key: keyof Settings) => Promise<void>;
	handleSetting: <K extends keyof Settings>(
		key: K,
		value: Settings[K],
	) => Promise<void>;
	confirmPendingChange: (pin: string) => Promise<void>;
	cancelPendingChange: () => void;
}

const AdminContext = createContext<AdminContextValue | null>(null);

export function useAdmin(): AdminContextValue {
	const ctx = useContext(AdminContext);
	if (!ctx) throw new Error("useAdmin must be used within AdminProvider");
	return ctx;
}

const defaultSettings: Settings = {
	open_on_startup: true,
	force_authentication: true,
	admin_gate: "off",
};

export function AdminProvider({ children }: { children: ReactNode }) {
	const [vaults, setVaults] = useState<VaultStatus[]>([]);
	const [keys, setKeys] = useState<KeyInfo[]>([]);
	const [settings, setSettings] = useState<Settings>(defaultSettings);
	const [error, setError] = useState("");
	const [pendingChange, setPendingChange] =
		useState<PendingSettingsChange | null>(null);

	const refresh = useCallback(async () => {
		try {
			const [status, keyList, s] = await Promise.all([
				api.getStatus(),
				api.listKeys(),
				api.getSettings(),
			]);
			setVaults(status.vaults || []);
			setKeys(keyList || []);
			setSettings(s);
		} catch {}
	}, []);

	useEffect(() => {
		refresh();
	}, [refresh]);

	const handleToggle = useCallback(async (key: keyof Settings) => {
		if (secureSettingKeys.has(key)) {
			// Don't optimistically update — wait for PIN confirmation
			setSettings((prev) => {
				const updated = { ...prev, [key]: !prev[key] };
				setPendingChange({ updated, previous: prev });
				return prev; // keep current state until confirmed
			});
		} else {
			setSettings((prev) => {
				const updated = { ...prev, [key]: !prev[key] };
				api.updateSettings(updated, "").catch((err: unknown) => {
					setError(friendlyError(err));
					setSettings(prev);
				});
				return updated;
			});
		}
	}, []);

	const handleSetting = useCallback(
		async <K extends keyof Settings>(key: K, value: Settings[K]) => {
			if (secureSettingKeys.has(key)) {
				setSettings((prev) => {
					const updated = { ...prev, [key]: value };
					setPendingChange({ updated, previous: prev });
					return prev;
				});
			} else {
				setSettings((prev) => {
					const updated = { ...prev, [key]: value };
					api.updateSettings(updated, "").catch((err: unknown) => {
						setError(friendlyError(err));
						setSettings(prev);
					});
					return updated;
				});
			}
		},
		[],
	);

	const confirmPendingChange = useCallback(
		async (pin: string) => {
			if (!pendingChange) return;
			try {
				await api.updateSettings(pendingChange.updated, pin);
				setSettings(pendingChange.updated); // apply on success
				setPendingChange(null);
			} catch (err: unknown) {
				setError(friendlyError(err));
				setPendingChange(null);
			}
		},
		[pendingChange],
	);

	const cancelPendingChange = useCallback(() => {
		if (pendingChange) {
			setSettings(pendingChange.previous);
			setPendingChange(null);
		}
	}, [pendingChange]);

	return (
		<AdminContext.Provider
			value={{
				vaults,
				keys,
				settings,
				error,
				pendingChange,
				refresh,
				setError,
				handleToggle,
				handleSetting,
				confirmPendingChange,
				cancelPendingChange,
			}}
		>
			{children}
		</AdminContext.Provider>
	);
}

export type { AdminContextValue };
