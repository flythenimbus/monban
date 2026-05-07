import { Events } from "@wailsio/runtime";
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { Lock } from "./components/icons/Lock";
import { useVaultProgress } from "./hooks/useVaultProgress";
import { AdminPanel } from "./screens/AdminPanel/AdminPanel";
import {
	type AuthorizeRequest,
	AuthorizeScreen,
} from "./screens/AuthorizeScreen/AuthorizeScreen";
import { CryptoProgressScreen } from "./screens/CryptoProgressScreen/CryptoProgressScreen";
import { LockScreen } from "./screens/LockScreen/LockScreen";
import { SetupScreen } from "./screens/SetupScreen/SetupScreen";

type View = "loading" | "setup" | "lock" | "admin" | "authorize";

function App() {
	const [view, setView] = useState<View>("loading");
	const [rollbackWarning, setRollbackWarning] = useState(false);
	const [authorizeReq, setAuthorizeReq] = useState<AuthorizeRequest | null>(
		null,
	);
	const vaultProgress = useVaultProgress();
	// N14: second-FIDO2-touch overlay during plugin install_pkg. Named
	// so the user knows the touch they're about to give authorizes
	// running a system installer as root, not just the download step.
	const [secondTouchPlugin, setSecondTouchPlugin] = useState<string | null>(
		null,
	);
	// Remember what the user was looking at when a plugin auth takes over,
	// so we can restore it after the prompt resolves.
	const prevViewRef = useRef<View>("admin");

	const checkState = useCallback(async () => {
		try {
			// Pending plugin auth takes priority over every other view —
			// the cold-start path is SecurityAgent launching us via
			// open -a Monban to collect a PIN, and we must never render
			// the lock (or admin) screen even for a frame on the way to
			// the authorize screen. This was a known flash in v0.4.0's
			// IPC auth flow; the fix is to check pending FIRST and
			// return early so getStatus never runs on that path.
			const pending = await api.getPendingPluginPinTouch();
			if (pending) {
				setAuthorizeReq(pending);
				setView("authorize");
				return;
			}

			const status = await api.getStatus();
			const base: View = !status.registered
				? "setup"
				: status.locked
					? "lock"
					: "admin";
			prevViewRef.current = base;
			setView(base);
		} catch {
			setView("setup");
		}
	}, []);

	const enterAuthorize = useCallback((req: AuthorizeRequest) => {
		setView((cur) => {
			if (cur !== "authorize" && cur !== "loading") {
				prevViewRef.current = cur;
			}
			return "authorize";
		});
		setAuthorizeReq(req);
	}, []);

	const exitAuthorize = useCallback(() => {
		setAuthorizeReq(null);
		setView(prevViewRef.current);
	}, []);

	useEffect(() => {
		checkState();
		const offLocked = Events.On("app:locked", () => setView("lock"));
		const offRollback = Events.On("app:config-rollback-detected", () =>
			setRollbackWarning(true),
		);
		const offPinTouch = Events.On(
			"plugin:pin-touch-request",
			(event: { data: AuthorizeRequest }) => enterAuthorize(event.data),
		);
		const offPinTouchCancelled = Events.On(
			"plugin:pin-touch-cancelled",
			(event: { data: { id: string } }) => {
				setAuthorizeReq((current) =>
					current?.id === event.data.id ? null : current,
				);
				setView((cur) => (cur === "authorize" ? prevViewRef.current : cur));
			},
		);
		const offSecondTouch = Events.On(
			"install:second-touch-required",
			(event: { data: { pluginName: string; displayName: string } }) =>
				setSecondTouchPlugin(event.data.displayName || event.data.pluginName),
		);
		const offSecondTouchDone = Events.On("install:second-touch-complete", () =>
			setSecondTouchPlugin(null),
		);
		return () => {
			offLocked();
			offRollback();
			offPinTouch();
			offPinTouchCancelled();
			offSecondTouch();
			offSecondTouchDone();
		};
	}, [checkState, enterAuthorize]);

	const body = (() => {
		// Vault encrypt/decrypt takes over the window as a top-level
		// screen, adjacent to setup/lock/admin/authorize. It owns its
		// own size via useAutoResize so the host window collapses to
		// just what the progress UI needs.
		if (vaultProgress) {
			return <CryptoProgressScreen progress={vaultProgress} />;
		}
		switch (view) {
			case "loading":
				return (
					<div className="gradient-bg flex items-center justify-center min-h-screen text-text-secondary">
						Loading...
					</div>
				);
			case "setup":
				return (
					<SetupScreen
						onComplete={() => {
							api.exitFullscreen();
							setView("admin");
						}}
					/>
				);
			case "lock":
				return (
					<LockScreen
						onUnlock={() => {
							api.exitFullscreen();
							setView("admin");
							void api.promptUpdateIfAvailable();
						}}
					/>
				);
			case "admin":
				return (
					<AdminPanel
						rollbackWarning={rollbackWarning}
						onDismissRollback={() => setRollbackWarning(false)}
					/>
				);
			case "authorize":
				return authorizeReq ? (
					<AuthorizeScreen request={authorizeReq} onDone={exitAuthorize} />
				) : null;
		}
	})();

	return (
		<>
			{body}
			{secondTouchPlugin && (
				<SecondTouchOverlay pluginName={secondTouchPlugin} />
			)}
		</>
	);
}

/**
 * SecondTouchOverlay surfaces the second FIDO2 touch required before
 * a plugin's install_pkg runs as root. Without this the backend's
 * second fidoReauth is a silent touch the user doesn't realise
 * authorises the installer, not just the download. Part of N14.
 */
function SecondTouchOverlay({ pluginName }: { pluginName: string }) {
	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-md p-6">
			<div className="glass rounded-2xl max-w-sm w-full p-6 text-center">
				<div className="flex justify-center mb-5">
					<div className="relative">
						<div className="absolute inset-0 rounded-full bg-accent/20 animate-ping" />
						<div className="relative w-14 h-14 rounded-full bg-accent/15 text-accent flex items-center justify-center [&_svg]:size-6">
							<Lock />
						</div>
					</div>
				</div>
				<h2 className="text-base font-semibold text-text mb-2">
					Authorize installer
				</h2>
				<p className="text-sm text-text-secondary leading-relaxed">
					<strong className="text-text font-medium">{pluginName}</strong> is
					about to run a system installer that modifies files outside Monban.
				</p>
				<div className="mt-5 pt-4 border-t border-black/5 dark:border-white/5">
					<p className="text-xs text-accent animate-pulse motion-reduce:animate-none">
						Touch your security key to confirm
					</p>
				</div>
			</div>
		</div>
	);
}

export default App;
