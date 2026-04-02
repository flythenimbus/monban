import { useState, useEffect, useCallback } from "react";
import { Clipboard } from "@wailsio/runtime";
import { api } from "../api";
import { friendlyError } from "../errors";
import { useAutoResize } from "../useAutoResize";
import { Toggle, Tabs, Input, Select, Alert } from "./ui";
import type { VaultStatus, KeyInfo, Settings, SudoGateMode } from "../types";

export function AdminPanel() {
  const contentRef = useAutoResize();
  const [vaults, setVaults] = useState<VaultStatus[]>([]);
  const [keys, setKeys] = useState<KeyInfo[]>([]);
  const [settings, setSettings] = useState<Settings>({
    open_on_startup: true,
    force_authentication: true,
    sudo_gate: "off",
  });
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

  const handleToggle = async (key: keyof Settings) => {
    const updated = { ...settings, [key]: !settings[key] };
    setSettings(updated);
    try {
      await api.updateSettings(updated);
    } catch (err: any) {
      setError(friendlyError(err));
      setSettings(settings);
    }
  };

  const handleSetting = async <K extends keyof Settings>(key: K, value: Settings[K]) => {
    const updated = { ...settings, [key]: value };
    setSettings(updated);
    try {
      await api.updateSettings(updated);
    } catch (err: any) {
      setError(friendlyError(err));
      setSettings(settings);
    }
  };

  return (
    <div ref={contentRef} className="gradient-bg flex flex-col p-6 pt-14">
      <div className="flex items-center justify-between mb-5">
        <h1 className="text-lg font-semibold text-text">Monban</h1>
        <span className="text-accent text-xs font-medium px-2 py-1 rounded-full bg-accent/10">Unlocked</span>
      </div>

      {error && (
        <div className="mb-4">
          <Alert onDismiss={() => setError("")}>{error}</Alert>
        </div>
      )}

      <Tabs
        tabs={[
          {
            key: "general",
            label: "General",
            content: (
              <GeneralTab
                settings={settings}
                onToggle={handleToggle}
                onSetting={handleSetting}
                vaults={vaults}
                onError={setError}
                onRefresh={refresh}
              />
            ),
          },
          {
            key: "keys",
            label: "Keys",
            content: (
              <KeysTab
                keys={keys}
                onError={setError}
                onRefresh={refresh}
              />
            ),
          },
        ]}
      />
    </div>
  );
}

function GeneralTab({
  settings,
  onToggle,
  onSetting,
  vaults,
  onError,
  onRefresh,
}: {
  settings: Settings;
  onToggle: (key: keyof Settings) => void;
  onSetting: <K extends keyof Settings>(key: K, value: Settings[K]) => void;
  vaults: VaultStatus[];
  onError: (msg: string) => void;
  onRefresh: () => Promise<void>;
}) {
  const [inputPath, setInputPath] = useState("");
  const [adding, setAdding] = useState(false);
  const [sudoCmd, setSudoCmd] = useState("");
  const [copied, setCopied] = useState(false);

  const handleSudoGate = async (value: SudoGateMode) => {
    onSetting("sudo_gate", value);
    try {
      const cmd = await api.getSudoGateCommand(value);
      setSudoCmd(cmd || "");
    } catch {
      setSudoCmd("");
    }
  };

  const handleAdd = async () => {
    if (!inputPath) return;
    setAdding(true);
    onError("");
    try {
      await api.addFolder(inputPath);
      setInputPath("");
      await onRefresh();
    } catch (err: any) {
      // If the path is a file, try addFile instead
      const msg = typeof err === "string" ? err : err?.message || err?.error || String(err);
      if (/not a directory/i.test(msg)) {
        try {
          await api.addFile(inputPath);
          setInputPath("");
          await onRefresh();
          return;
        } catch (fileErr: any) {
          onError(friendlyError(fileErr));
          return;
        }
      }
      onError(friendlyError(err));
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (vaultPath: string) => {
    try {
      await api.removeFolder(vaultPath);
      await onRefresh();
    } catch (err: any) {
      onError(friendlyError(err));
    }
  };

  return (
    <div className="space-y-5">
      <div className="glass rounded-xl divide-y divide-black/5 dark:divide-white/5">
        <div className="flex items-center justify-between px-4 py-3">
          <div>
            <div className="text-sm font-medium text-text">Open on startup</div>
            <div className="text-xs text-text-secondary">Launch Monban when you log in</div>
          </div>
          <Toggle checked={settings.open_on_startup} onChange={() => onToggle("open_on_startup")} label="Open on startup" />
        </div>
        <div className="flex items-center justify-between px-4 py-3">
          <div>
            <div className="text-sm font-medium text-text">Force authentication</div>
            <div className="text-xs text-text-secondary">Fullscreen lock, can't be dismissed</div>
          </div>
          <Toggle checked={settings.force_authentication} onChange={() => onToggle("force_authentication")} label="Force authentication" />
        </div>
        <div className="flex items-center justify-between px-4 py-3">
          <div>
            <div className="text-sm font-medium text-text">Sudo gate</div>
            <div className="text-xs text-text-secondary">Require YubiKey for sudo</div>
          </div>
          <Select
            label="Sudo gate"
            value={settings.sudo_gate || "off"}
            onChange={(v) => handleSudoGate(v as SudoGateMode)}
            options={[
              { value: "off", label: "Off" },
              { value: "default", label: "Default" },
              { value: "strict", label: "Strict" },
            ]}
          />
        </div>
        {sudoCmd && (
          <div className="px-4 py-3">
            <div className="text-xs text-text-secondary mb-2">Run in Terminal to apply:</div>
            <div className="flex items-center gap-2 bg-black/30 rounded-lg px-3 py-2">
              <code className="text-xs font-mono text-white/90 break-all flex-1">{sudoCmd}</code>
              <button
                onClick={() => { Clipboard.SetText(sudoCmd); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
                className="shrink-0 text-xs text-accent hover:text-accent/80 transition-colors cursor-pointer font-medium"
              >
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
          </div>
        )}
      </div>

      <div>
        <h2 className="text-sm font-medium text-text-secondary mb-3">Protected Items</h2>
        {vaults.length === 0 ? (
          <div className="glass rounded-xl p-5 text-center">
            <p className="text-text-secondary text-sm">Nothing protected yet</p>
            <p className="text-text-secondary text-xs mt-1">Add a folder or file to start encrypting</p>
          </div>
        ) : (
          <div className="space-y-2">
            {vaults.map((v) => (
              <div key={v.path} className="glass rounded-xl px-4 py-3 flex items-center justify-between">
                <div>
                  <div className="text-sm font-medium text-text">{v.label}</div>
                  <div className="text-xs text-text-secondary">{v.path}</div>
                </div>
                <button
                  onClick={() => handleRemove(v.path)}
                  aria-label={`Remove ${v.label}`}
                  className="text-xs text-text-secondary hover:text-error transition-colors cursor-pointer"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}

        <div className="flex gap-2 mt-3">
          <Input
            type="text"
            label="Path"
            placeholder="Folder or file path"
            value={inputPath}
            onChange={(e) => setInputPath(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAdd()}
            className="flex-1"
          />
          <button
            onClick={handleAdd}
            disabled={!inputPath || adding}
            className="btn-primary !w-auto px-5"
          >
            {adding ? "..." : "Add"}
          </button>
        </div>
      </div>
    </div>
  );
}

function KeysTab({
  keys,
  onError,
  onRefresh,
}: {
  keys: KeyInfo[];
  onError: (msg: string) => void;
  onRefresh: () => Promise<void>;
}) {
  const [showAdd, setShowAdd] = useState(false);
  const [pin, setPin] = useState("");
  const [label, setLabel] = useState("");
  const [adding, setAdding] = useState(false);

  const handleAdd = async () => {
    if (!pin || !label) return;
    setAdding(true);
    try {
      await api.register(pin, label);
      setShowAdd(false);
      setPin("");
      setLabel("");
      await onRefresh();
    } catch (err: any) {
      onError(friendlyError(err));
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (credId: string) => {
    try {
      await api.removeKey(credId);
      await onRefresh();
    } catch (err: any) {
      onError(friendlyError(err));
    }
  };

  return (
    <div className="space-y-3 flex-1">
      {keys.map((k) => (
        <div key={k.credential_id} className="glass rounded-xl px-4 py-3 flex items-center justify-between">
          <span className="text-sm font-medium text-text">{k.label}</span>
          <button
            onClick={() => handleRemove(k.credential_id)}
            disabled={keys.length <= 1}
            aria-label={`Remove ${k.label}`}
            className="text-xs text-text-secondary hover:text-error transition-colors disabled:opacity-30"
          >
            Remove
          </button>
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
            label="YubiKey PIN"
            placeholder="YubiKey PIN"
            value={pin}
            onChange={(e) => setPin(e.target.value)}
          />
          <div className="flex gap-2">
            <button
              onClick={handleAdd}
              disabled={!pin || !label || adding}
              className="btn-primary"
            >
              {adding ? "Registering..." : "Register Key"}
            </button>
            <button
              onClick={() => { setShowAdd(false); setPin(""); setLabel(""); }}
              className="btn-secondary"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <button
          onClick={() => setShowAdd(true)}
          className="text-sm text-accent hover:opacity-80 transition-opacity"
        >
          + Add Key
        </button>
      )}
    </div>
  );
}
