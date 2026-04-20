import { Events } from "@wailsio/runtime";
import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { PluginPinTouchOverlay } from "./components";
import { AdminPanel } from "./screens/AdminPanel/AdminPanel";
import { LockScreen } from "./screens/LockScreen/LockScreen";
import { SetupScreen } from "./screens/SetupScreen/SetupScreen";

type View = "loading" | "setup" | "lock" | "admin";

function App() {
	const [view, setView] = useState<View>("loading");
	const [rollbackWarning, setRollbackWarning] = useState(false);

	const checkState = useCallback(async () => {
		try {
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
		return () => {
			offLocked();
			offRollback();
		};
	}, [checkState]);

	let screen: React.ReactNode;
	switch (view) {
		case "loading":
			screen = (
				<div className="gradient-bg flex items-center justify-center min-h-screen text-text-secondary">
					Loading...
				</div>
			);
			break;
		case "setup":
			screen = (
				<SetupScreen
					onComplete={() => {
						api.exitFullscreen();
						setView("admin");
					}}
				/>
			);
			break;
		case "lock":
			screen = (
				<LockScreen
					onUnlock={() => {
						api.exitFullscreen();
						setView("admin");
					}}
				/>
			);
			break;
		case "admin":
			screen = (
				<AdminPanel
					rollbackWarning={rollbackWarning}
					onDismissRollback={() => setRollbackWarning(false)}
				/>
			);
			break;
	}

	return (
		<>
			{screen}
			<PluginPinTouchOverlay />
		</>
	);
}

export default App;
