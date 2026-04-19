import { Events } from "@wailsio/runtime";
import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { IPCAuthDialog } from "./components/IPCAuthDialog";
import { AdminPanel } from "./screens/AdminPanel/AdminPanel";
import { LockScreen } from "./screens/LockScreen/LockScreen";
import { SetupScreen } from "./screens/SetupScreen/SetupScreen";

type View = "loading" | "setup" | "lock" | "admin" | "ipc-auth";

interface IPCAuthRequest {
	user: string;
	service: string;
}

function App() {
	const [view, setView] = useState<View>("loading");
	const [previousView, setPreviousView] = useState<View>("loading");
	const [rollbackWarning, setRollbackWarning] = useState(false);
	const [ipcAuth, setIpcAuth] = useState<IPCAuthRequest | null>(null);

	const checkState = useCallback(async () => {
		try {
			// A pending IPC auth request (typically from the authorization
			// plugin triggered by a system-level admin prompt) takes priority
			// over every other view. Handles the cold-start race where the
			// plugin connected and emitted the event before Events.On was
			// subscribed.
			const pending = await api.getPendingIPCAuth();
			if (pending) {
				setIpcAuth(pending);
				setView("ipc-auth");
				return;
			}

			const status = await api.getStatus();
			if (!status.registered) {
				setView("setup");
			} else if (status.locked) {
				setView("lock");
			} else {
				setView("admin");
			}
		} catch {
			setView("setup");
		}
	}, []);

	useEffect(() => {
		checkState();
		const offLocked = Events.On("app:locked", () => setView("lock"));
		const offRollback = Events.On("app:config-rollback-detected", () =>
			setRollbackWarning(true),
		);
		const offIpcAuth = Events.On("ipc:auth-request", (event: { data: IPCAuthRequest }) => {
			console.log("[ipc] received ipc:auth-request", event.data);
			setIpcAuth(event.data);
			setView((prev) => {
				console.log("[ipc] switching view from", prev, "to ipc-auth");
				setPreviousView(prev);
				return "ipc-auth";
			});
		});
		return () => {
			offLocked();
			offRollback();
			offIpcAuth();
		};
	}, [checkState]);

	const handleIpcDone = () => {
		setIpcAuth(null);
		setView(previousView);
		api.hideToTray();
	};

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
		case "ipc-auth":
			return ipcAuth ? (
				<IPCAuthDialog
					service={ipcAuth.service}
					user={ipcAuth.user}
					onDone={handleIpcDone}
				/>
			) : null;
	}
}

export default App;
