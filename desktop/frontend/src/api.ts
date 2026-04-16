import * as App from "../bindings/monban/internal/app/app";
import type {
	AppStatus,
	DiskSpaceInfo,
	KeyInfo,
	Settings,
	UpdateInfo,
} from "./types";

export const api = {
	isRegistered: (): Promise<boolean> => App.IsRegistered(),

	detectDevice: (): Promise<boolean> => App.DetectDevice(),

	register: (pin: string, label: string): Promise<void> =>
		App.Register(pin, label),

	unlock: (pin: string): Promise<void> => App.Unlock(pin),

	lock: (): Promise<void> => App.Lock(),

	getStatus: (): Promise<AppStatus> =>
		App.GetStatus() as unknown as Promise<AppStatus>,

	listKeys: (): Promise<KeyInfo[]> =>
		App.ListKeys() as unknown as Promise<KeyInfo[]>,

	removeKey: (credentialId: string, pin: string): Promise<void> =>
		App.RemoveKey(credentialId, pin),

	checkDiskSpace: (path: string): Promise<DiskSpaceInfo> =>
		App.CheckDiskSpace(path) as unknown as Promise<DiskSpaceInfo>,

	addPath: (path: string, pin: string): Promise<void> => App.AddPath(path, pin),

	removeFolder: (vaultPath: string, pin: string): Promise<void> =>
		App.RemoveFolder(vaultPath, pin),

	decryptLazyVault: (path: string, pin: string): Promise<void> =>
		App.DecryptLazyVault(path, pin),

	lockVault: (path: string): Promise<void> => App.LockVault(path),

	updateVaultMode: (path: string, mode: string, pin: string): Promise<void> =>
		App.UpdateVaultMode(path, mode, pin),

	exitFullscreen: (): Promise<void> => App.ExitFullscreen(),

	enterFullscreen: (): Promise<void> => App.EnterFullscreen(),

	getSettings: (): Promise<Settings> =>
		App.GetSettings() as unknown as Promise<Settings>,

	updateSettings: (settings: Settings, pin: string): Promise<void> =>
		App.UpdateSettings(
			settings as unknown as Parameters<typeof App.UpdateSettings>[0],
			pin,
		),

	getAdminGateCommand: (mode: string): Promise<string> =>
		App.GetAdminGateCommand(mode),

	handleIPCAuth: (pin: string): Promise<void> => App.HandleIPCAuth(pin),

	cancelIPCAuth: (): Promise<void> => App.CancelIPCAuth(),

	hideToTray: (): Promise<void> => App.HideToTray(),

	revealSecureConfig: (): Promise<void> => App.RevealSecureConfig(),

	getVersion: (): Promise<string> => App.GetVersion(),

	checkForUpdate: (): Promise<UpdateInfo> =>
		App.CheckForUpdate() as unknown as Promise<UpdateInfo>,
};
