import { Events } from "@wailsio/runtime";
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { AdminPanel } from "./screens/AdminPanel/AdminPanel";
import {
	type AuthorizeRequest,
	AuthorizeScreen,
} from "./screens/AuthorizeScreen/AuthorizeScreen";
import { LockScreen } from "./screens/LockScreen/LockScreen";
import { SetupScreen } from "./screens/SetupScreen/SetupScreen";

type View = "loading" | "setup" | "lock" | "admin" | "authorize";

function App() {
	const [view, setView] = useState<View>("loading");
	const [rollbackWarning, setRollbackWarning] = useState(false);
	const [authorizeReq, setAuthorizeReq] = useState<AuthorizeRequest | null>(
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
		return () => {
			offLocked();
			offRollback();
			offPinTouch();
			offPinTouchCancelled();
		};
	}, [checkState, enterAuthorize]);

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
}

export default App;
