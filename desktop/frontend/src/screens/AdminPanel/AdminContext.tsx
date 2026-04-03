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

interface AdminContextValue {
	vaults: VaultStatus[];
	keys: KeyInfo[];
	settings: Settings;
	error: string;
	refresh: () => Promise<void>;
	setError: (msg: string) => void;
	handleToggle: (key: keyof Settings) => Promise<void>;
	handleSetting: <K extends keyof Settings>(
		key: K,
		value: Settings[K],
	) => Promise<void>;
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
	sudo_gate: "off",
};

export function AdminProvider({ children }: { children: ReactNode }) {
	const [vaults, setVaults] = useState<VaultStatus[]>([]);
	const [keys, setKeys] = useState<KeyInfo[]>([]);
	const [settings, setSettings] = useState<Settings>(defaultSettings);
	const [error, setError] = useState("");

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
		setSettings((prev) => {
			const updated = { ...prev, [key]: !prev[key] };
			api.updateSettings(updated).catch((err: unknown) => {
				setError(friendlyError(err));
				setSettings(prev);
			});
			return updated;
		});
	}, []);

	const handleSetting = useCallback(
		async <K extends keyof Settings>(key: K, value: Settings[K]) => {
			setSettings((prev) => {
				const updated = { ...prev, [key]: value };
				api.updateSettings(updated).catch((err: unknown) => {
					setError(friendlyError(err));
					setSettings(prev);
				});
				return updated;
			});
		},
		[],
	);

	return (
		<AdminContext.Provider
			value={{
				vaults,
				keys,
				settings,
				error,
				refresh,
				setError,
				handleToggle,
				handleSetting,
			}}
		>
			{children}
		</AdminContext.Provider>
	);
}

export type { AdminContextValue };
