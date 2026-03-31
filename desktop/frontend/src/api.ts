import * as App from "../bindings/monban/app";
import type { AppStatus, KeyInfo, DiskSpaceInfo, Settings } from "./types";

export const api = {
  isRegistered: (): Promise<boolean> => App.IsRegistered(),

  detectDevice: (): Promise<boolean> => App.DetectDevice(),

  register: (pin: string, label: string): Promise<void> =>
    App.Register(pin, label),

  unlock: (pin: string): Promise<void> => App.Unlock(pin),

  lock: (): Promise<void> => App.Lock(),

  getStatus: (): Promise<AppStatus> => App.GetStatus() as any,

  listKeys: (): Promise<KeyInfo[]> => App.ListKeys() as any,

  removeKey: (credentialId: string): Promise<void> =>
    App.RemoveKey(credentialId),

  checkDiskSpace: (path: string): Promise<DiskSpaceInfo> =>
    App.CheckDiskSpace(path) as any,

  addFolder: (path: string): Promise<void> => App.AddFolder(path),

  addFile: (path: string): Promise<void> => App.AddFile(path),

  removeFolder: (vaultPath: string): Promise<void> =>
    App.RemoveFolder(vaultPath),

  exitFullscreen: (): Promise<void> => App.ExitFullscreen(),

  enterFullscreen: (): Promise<void> => App.EnterFullscreen(),

  getSettings: (): Promise<Settings> => App.GetSettings() as any,

  updateSettings: (settings: Settings): Promise<void> =>
    App.UpdateSettings(settings as any),
};
