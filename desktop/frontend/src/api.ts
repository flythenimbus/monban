import * as App from "../bindings/monban/app";
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

	removeKey: (credentialId: string): Promise<void> =>
		App.RemoveKey(credentialId),

	checkDiskSpace: (path: string): Promise<DiskSpaceInfo> =>
		App.CheckDiskSpace(path) as unknown as Promise<DiskSpaceInfo>,

	addPath: (path: string): Promise<void> => App.AddPath(path),

	addFolder: (path: string): Promise<void> => App.AddFolder(path),

	addFile: (path: string): Promise<void> => App.AddFile(path),

	removeFolder: (vaultPath: string): Promise<void> =>
		App.RemoveFolder(vaultPath),

	decryptLazyVault: (path: string, pin: string): Promise<void> =>
		App.DecryptLazyVault(path, pin),

	lockVault: (path: string): Promise<void> => App.LockVault(path),

	updateVaultMode: (path: string, mode: string, pin: string): Promise<void> =>
		App.UpdateVaultMode(path, mode, pin),

	exitFullscreen: (): Promise<void> => App.ExitFullscreen(),

	enterFullscreen: (): Promise<void> => App.EnterFullscreen(),

	getSettings: (): Promise<Settings> =>
		App.GetSettings() as unknown as Promise<Settings>,

	updateSettings: (settings: Settings): Promise<void> =>
		App.UpdateSettings(
			settings as unknown as Parameters<typeof App.UpdateSettings>[0],
		),

	getSudoGateCommand: (mode: string): Promise<string> =>
		App.GetSudoGateCommand(mode),

	revealSecureConfig: (): Promise<void> => App.RevealSecureConfig(),

	getVersion: (): Promise<string> => App.GetVersion(),

	checkForUpdate: (): Promise<UpdateInfo> =>
		App.CheckForUpdate() as unknown as Promise<UpdateInfo>,
};
