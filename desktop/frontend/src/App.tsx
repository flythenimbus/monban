import { Events } from "@wailsio/runtime";
import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { AdminPanel } from "./screens/AdminPanel/AdminPanel";
import { LockScreen } from "./screens/LockScreen/LockScreen";
import { SetupScreen } from "./screens/SetupScreen/SetupScreen";

type View = "loading" | "setup" | "lock" | "admin";

function App() {
	const [view, setView] = useState<View>("loading");

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
		return Events.On("app:locked", () => setView("lock"));
	}, [checkState]);

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
			return <AdminPanel />;
	}
}

export default App;
