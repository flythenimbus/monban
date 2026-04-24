import { useState } from "react";
import { api } from "../../api";
import { Alert, Button, Input, StatusText } from "../../components";
import { useAutoResize } from "../../hooks/useAutoResize";
import { useDevicePolling } from "../../hooks/useDevicePolling";
import { friendlyError } from "../../util/errors";

export interface AuthorizeRequest {
	id: string;
	title: string;
	subtitle: string;
}

interface Props {
	request: AuthorizeRequest;
	onDone: () => void;
}

type AuthState = "idle" | "waiting_touch" | "error" | "success";

/**
 * Compact full-window authorization prompt driven by a plugin's
 * request_pin_touch RPC. Ported from the old IPCAuthDialog layout —
 * flat content + useAutoResize so the host window collapses to just
 * what this view needs (<200 px tall) instead of the full-screen
 * centred card.
 *
 * Independent of Monban's lock state: the plugin's auth is a separate
 * concern from Monban's vault state, so this renders identically
 * whether the app is locked or unlocked.
 */
export function AuthorizeScreen({ request, onDone }: Props) {
	const contentRef = useAutoResize();
	const [pin, setPin] = useState("");
	const [state, setState] = useState<AuthState>("idle");
	const [error, setError] = useState("");
	const deviceConnected = useDevicePolling();

	const handleAuthenticate = async () => {
		if (!pin) return;
		setState("waiting_touch");
		setError("");
		try {
			await api.respondPluginPinTouch(request.id, pin);
			setState("success");
			// Briefly show the success state, then get out of the way —
			// the user invoked sudo / a System Settings pane from
			// outside Monban, so Monban's window shouldn't linger after
			// the auth completes.
			setTimeout(() => {
				api.hideWindow().catch(() => {});
				onDone();
			}, 400);
		} catch (err: unknown) {
			setError(friendlyError(err));
			setState("error");
			setPin("");
		}
	};

	const handleCancel = async () => {
		try {
			await api.cancelPluginPinTouch(request.id);
		} catch {
			/* best-effort — always dismiss */
		}
		api.hideWindow().catch(() => {});
		onDone();
	};

	return (
		<div
			ref={contentRef}
			className="gradient-bg flex flex-col gap-4 p-8 pt-14 select-none"
			style={{ WebkitAppRegion: "drag" } as React.CSSProperties}
		>
			<div
				className="flex flex-col gap-4"
				style={{ WebkitAppRegion: "no-drag" } as React.CSSProperties}
			>
				<div className="text-center">
					<h1 className="text-lg font-semibold text-text">
						{request.title || "Authorization requested"}
					</h1>
					<p aria-live="polite" className="text-text-secondary text-sm mt-1">
						{!deviceConnected
							? "Insert your security key to continue"
							: request.subtitle || "Enter PIN and touch your security key"}
					</p>
				</div>

				{!deviceConnected ? (
					<>
						<StatusText pulse>Waiting for security key…</StatusText>
						<Button variant="secondary" onClick={handleCancel}>
							Cancel
						</Button>
					</>
				) : state === "waiting_touch" ? (
					<StatusText variant="accent" pulse>
						Touch your security key…
					</StatusText>
				) : state === "success" ? (
					<StatusText variant="success">Authorized</StatusText>
				) : (
					<>
						{state === "error" && <Alert>{error}</Alert>}
						<Input
							type="password"
							label="Security key PIN"
							placeholder="Security key PIN"
							value={pin}
							onChange={(e) => setPin(e.target.value)}
							onKeyDown={(e) =>
								e.key === "Enter" && pin && handleAuthenticate()
							}
							autoFocus
						/>
						<div className="flex gap-2">
							<Button
								onClick={handleAuthenticate}
								disabled={!pin}
								className="flex-1"
							>
								Authenticate
							</Button>
							<Button
								variant="secondary"
								onClick={handleCancel}
								className="flex-1"
							>
								Cancel
							</Button>
						</div>
					</>
				)}
			</div>
		</div>
	);
}
