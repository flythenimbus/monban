import { useCallback, useEffect, useState } from "react";
import { api } from "../../../api";
import {
	Button,
	CollapsibleCard,
	PinAuth,
	SchemaField,
} from "../../../components";
import type {
	AvailablePlugin,
	PluginSettingsSchema,
	PluginStatus,
} from "../../../types";
import { friendlyError } from "../../../util/errors";
import { useAdmin } from "../AdminContext";

type SettingsMap = Record<string, unknown>;

interface PendingSave {
	name: string;
	displayName: string;
	settings: SettingsMap;
}

interface PendingUninstall {
	name: string;
	displayName: string;
}

interface PendingInstall {
	name: string;
	displayName: string;
}

export function PluginsTab() {
	const { setError } = useAdmin();
	const [plugins, setPlugins] = useState<PluginStatus[] | null>(null);
	const [available, setAvailable] = useState<AvailablePlugin[]>([]);
	const [expanded, setExpanded] = useState<string | null>(null);
	const [drafts, setDrafts] = useState<Record<string, SettingsMap>>({});
	const [pendingSave, setPendingSave] = useState<PendingSave | null>(null);
	const [pendingUninstall, setPendingUninstall] =
		useState<PendingUninstall | null>(null);
	const [pendingInstall, setPendingInstall] = useState<PendingInstall | null>(
		null,
	);
	const [installing, setInstalling] = useState<string | null>(null);

	const refresh = useCallback(async () => {
		try {
			const [list, avail] = await Promise.all([
				api.listPlugins(),
				api.listAvailablePlugins(),
			]);
			setPlugins(list);
			setAvailable(avail);
			const next: Record<string, SettingsMap> = {};
			for (const p of list) {
				next[p.name] = await api.getPluginSettings(p.name);
			}
			setDrafts(next);
		} catch (err: unknown) {
			setError(friendlyError(err));
		}
	}, [setError]);

	useEffect(() => {
		refresh();
	}, [refresh]);

	const handleDraftChange = (name: string, key: string, value: unknown) => {
		setDrafts((prev) => ({
			...prev,
			[name]: { ...(prev[name] ?? {}), [key]: value },
		}));
	};

	const confirmSave = async (pin: string) => {
		if (!pendingSave) return;
		setError("");
		try {
			await api.updatePluginSettings(
				pendingSave.name,
				pendingSave.settings,
				pin,
			);
			setPendingSave(null);
			await refresh();
		} catch (err: unknown) {
			setError(friendlyError(err));
			setPendingSave(null);
		}
	};

	const confirmUninstall = async (pin: string) => {
		if (!pendingUninstall) return;
		setError("");
		try {
			await api.uninstallPlugin(pendingUninstall.name, pin);
			setPendingUninstall(null);
			setExpanded(null);
			await refresh();
		} catch (err: unknown) {
			setError(friendlyError(err));
			setPendingUninstall(null);
		}
	};

	const confirmInstall = async (pin: string) => {
		if (!pendingInstall) return;
		setError("");
		setInstalling(pendingInstall.name);
		try {
			await api.installPlugin(pendingInstall.name, pin);
			setPendingInstall(null);
			await refresh();
		} catch (err: unknown) {
			setError(friendlyError(err));
			setPendingInstall(null);
		} finally {
			setInstalling(null);
		}
	};

	const availableNotInstalled = available.filter((a) => !a.installed);

	if (plugins === null) {
		return <div className="text-sm text-text-secondary">Loading plugins…</div>;
	}

	return (
		<div className="space-y-5">
			{plugins.length > 0 && (
				<section className="space-y-3">
					<h3 className="text-xs font-medium text-text-secondary uppercase tracking-wide">
						Installed
					</h3>
					{plugins.map((p) => {
						const schema = (p.settings ?? {}) as PluginSettingsSchema;
						const draft = drafts[p.name] ?? {};
						const isExpanded = expanded === p.name;
						const hasSettings = Object.keys(schema).length > 0;

						return (
							<CollapsibleCard
								key={p.name}
								open={isExpanded}
								onToggle={() => setExpanded(isExpanded ? null : p.name)}
								header={
									<div>
										<div className="flex items-center gap-2">
											<span className="text-sm font-medium text-text">
												{p.display_name || p.name}
											</span>
											<span className="text-xs text-text-secondary">
												v{p.version}
											</span>
											{!p.loaded && (
												<span className="text-xs px-1.5 py-0.5 rounded bg-red-500/15 text-red-500">
													not loaded
												</span>
											)}
										</div>
										{p.description && (
											<div className="text-xs text-text-secondary mt-0.5 truncate">
												{p.description}
											</div>
										)}
									</div>
								}
							>
								{hasSettings ? (
									Object.entries(schema).map(([key, spec]) => (
										<SchemaField
											key={key}
											fieldKey={key}
											spec={spec}
											value={draft[key] ?? spec.default}
											onChange={(v) => handleDraftChange(p.name, key, v)}
										/>
									))
								) : (
									<div className="text-xs text-text-secondary">
										This plugin has no settings.
									</div>
								)}

								<div className="pt-2 flex justify-end gap-2">
									<Button
										variant="danger"
										size="sm"
										onClick={() =>
											setPendingUninstall({
												name: p.name,
												displayName: p.display_name || p.name,
											})
										}
										disabled={pendingUninstall !== null}
									>
										Uninstall
									</Button>
									{hasSettings && (
										<Button
											size="sm"
											onClick={() =>
												setPendingSave({
													name: p.name,
													displayName: p.display_name || p.name,
													settings: draft,
												})
											}
											disabled={pendingSave !== null}
										>
											Save
										</Button>
									)}
								</div>
							</CollapsibleCard>
						);
					})}
				</section>
			)}

			{availableNotInstalled.length > 0 && (
				<section className="space-y-3">
					<h3 className="text-xs font-medium text-text-secondary uppercase tracking-wide">
						Available
					</h3>
					{availableNotInstalled.map((a) => (
						<div
							key={a.name}
							className="glass rounded-xl px-4 py-3 flex items-center justify-between gap-3"
						>
							<div className="min-w-0 flex-1">
								<div className="flex items-center gap-2">
									<span className="text-sm font-medium text-text">
										{a.display_name || a.name}
									</span>
									<span className="text-xs text-text-secondary">
										v{a.version}
									</span>
								</div>
								{a.description && (
									<div className="text-xs text-text-secondary mt-0.5 truncate">
										{a.description}
									</div>
								)}
							</div>
							<Button
								size="sm"
								onClick={() =>
									setPendingInstall({
										name: a.name,
										displayName: a.display_name || a.name,
									})
								}
								disabled={pendingInstall !== null || installing !== null}
							>
								{installing === a.name ? "Installing…" : "Install"}
							</Button>
						</div>
					))}
				</section>
			)}

			{plugins.length === 0 && availableNotInstalled.length === 0 && (
				<div className="glass rounded-xl p-5 text-center">
					<p className="text-text-secondary text-sm">No plugins available</p>
				</div>
			)}

			{pendingSave && (
				<PinAuth
					label={`Authenticate to save ${pendingSave.displayName} settings`}
					onSubmit={confirmSave}
					onCancel={() => setPendingSave(null)}
				/>
			)}

			{pendingUninstall && (
				<PinAuth
					label={`Authenticate to uninstall ${pendingUninstall.displayName}`}
					onSubmit={confirmUninstall}
					onCancel={() => setPendingUninstall(null)}
				/>
			)}

			{pendingInstall && (
				<PinAuth
					label={`Authenticate to install ${pendingInstall.displayName}`}
					onSubmit={confirmInstall}
					onCancel={() => setPendingInstall(null)}
				/>
			)}
		</div>
	);
}
