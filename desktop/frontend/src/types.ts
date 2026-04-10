export type LockState =
	| "idle"
	| "waiting_touch"
	| "verifying"
	| "error"
	| "success";

export type SetupState =
	| "detect"
	| "pin"
	| "waiting_touch"
	| "registering"
	| "error"
	| "success";

export interface AppStatus {
	locked: boolean;
	registered: boolean;
	vaults: VaultStatus[];
}

export type DecryptMode = "eager" | "lazy" | "lazy_strict";

export interface VaultStatus {
	label: string;
	path: string;
	type?: string;
	locked: boolean;
	decrypt_mode?: DecryptMode;
}

export interface KeyInfo {
	label: string;
	credential_id: string;
}

export interface DiskSpaceInfo {
	folder_gb: number;
	free_gb: number;
	safe_to_migrate: boolean;
}

export type SudoGateMode = "off" | "default" | "strict";

export interface Settings {
	open_on_startup: boolean;
	force_authentication: boolean;
	sudo_gate: SudoGateMode;
}

export interface UpdateInfo {
	current_version: string;
	latest_version: string;
	update_available: boolean;
	release_url: string;
}
