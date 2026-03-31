export type LockState = "idle" | "waiting_touch" | "verifying" | "error" | "success";

export type SetupState = "detect" | "pin" | "waiting_touch" | "registering" | "error" | "success";

export interface AppStatus {
  locked: boolean;
  registered: boolean;
  vaults: VaultStatus[];
}

export interface VaultStatus {
  label: string;
  path: string;
  type?: string;
  locked: boolean;
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
