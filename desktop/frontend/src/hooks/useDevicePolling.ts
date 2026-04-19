import { useEffect, useState } from "react";
import { api } from "../api";

/**
 * Polls `api.detectDevice()` on an interval and returns whether a FIDO2
 * device is currently connected. Used by every screen that waits for the
 * user to plug in their security key (lock screen, admin-gate IPC dialog).
 */
export function useDevicePolling(intervalMs = 2000): boolean {
	const [connected, setConnected] = useState(false);

	useEffect(() => {
		const check = () => {
			api
				.detectDevice()
				.then(setConnected)
				.catch(() => setConnected(false));
		};
		check();
		const id = setInterval(check, intervalMs);
		return () => clearInterval(id);
	}, [intervalMs]);

	return connected;
}
