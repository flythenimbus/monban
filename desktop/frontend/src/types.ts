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

export interface Settings {
	open_on_startup: boolean;
	force_authentication: boolean;
}

export interface UpdateInfo {
	current_version: string;
	latest_version: string;
	update_available: boolean;
	release_url: string;
}

export type PluginSettingType =
	| "bool"
	| "string"
	| "int"
	| "url"
	| "list<string>";

export interface PluginSettingSpec {
	type: PluginSettingType;
	label?: string;
	description?: string;
	default?: unknown;
	required?: boolean;
}

export type PluginSettingsSchema = Record<string, PluginSettingSpec>;

export interface PluginStatus {
	name: string;
	display_name: string;
	version: string;
	description?: string;
	kind: string[];
	hooks?: string[];
	settings?: PluginSettingsSchema | null;
	dir: string;
	loaded: boolean;
}

export interface AvailablePlugin {
	name: string;
	display_name: string;
	version: string;
	description: string;
	installed: boolean;
}
