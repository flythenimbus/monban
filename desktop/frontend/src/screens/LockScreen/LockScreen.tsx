import { useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { Alert, GlassCard, Input, Logo, StatusText } from "../../components";
import { useAutoResize } from "../../hooks/useAutoResize";
import type { LockState, Settings } from "../../types";
import { friendlyError } from "../../util/errors";

interface Props {
	onUnlock: () => void;
}

export function LockScreen({ onUnlock }: Props) {
	const contentRef = useAutoResize();
	const [state, setState] = useState<LockState>("idle");
	const [pin, setPin] = useState("");
	const [error, setError] = useState("");
	const [forceAuth, setForceAuth] = useState(true);
	const [deviceConnected, setDeviceConnected] = useState(false);
	const pollRef = useRef<ReturnType<typeof setInterval>>();

	useEffect(() => {
		api
			.getSettings()
			.then((s: Settings) => setForceAuth(s.force_authentication))
			.catch(() => {});
	}, []);

	useEffect(() => {
		const check = () => {
			api
				.detectDevice()
				.then(setDeviceConnected)
				.catch(() => setDeviceConnected(false));
		};
		check();
		pollRef.current = setInterval(check, 2000);
		return () => clearInterval(pollRef.current);
	}, []);

	const handleUnlock = async () => {
		if (!pin) return;
		setState("waiting_touch");
		try {
			await api.unlock(pin);
			setState("success");
			setTimeout(onUnlock, 500);
		} catch (err) {
			setError(friendlyError(err));
			setState("error");
			setPin("");
		}
	};

	return (
		<div
			ref={contentRef}
			className={`gradient-bg flex flex-col items-center justify-center p-8 select-none ${forceAuth ? "min-h-screen" : "pt-14 pb-8"}`}
			style={{ WebkitAppRegion: "drag" } as React.CSSProperties}
		>
			<div className="mb-6 opacity-80">
				<Logo />
			</div>

			<GlassCard style={{ WebkitAppRegion: "no-drag" } as React.CSSProperties}>
				<div className="text-center">
					<h1 className="text-lg font-semibold text-text">Monban</h1>
					<p aria-live="polite" className="text-text-secondary text-sm mt-1">
						{!deviceConnected
							? "Insert your security key to continue"
							: "Enter PIN and touch your security key"}
					</p>
				</div>

				{!deviceConnected ? (
					<StatusText pulse>Waiting for security key...</StatusText>
				) : (
					<>
						<Input
							type="password"
							label="Security key PIN"
							placeholder="Security key PIN"
							value={pin}
							onChange={(e) => setPin(e.target.value)}
							onKeyDown={(e) => e.key === "Enter" && handleUnlock()}
							disabled={state === "waiting_touch" || state === "success"}
							autoFocus
						/>

						{state === "error" && <Alert>{error}</Alert>}

						{state === "waiting_touch" && (
							<StatusText variant="accent" pulse>
								Touch your security key...
							</StatusText>
						)}

						{state === "success" && (
							<StatusText variant="success">Unlocked</StatusText>
						)}

						{state === "idle" && (
							<div className="text-center text-text-secondary text-xs">
								Ready
							</div>
						)}

						<button
							type="button"
							onClick={handleUnlock}
							disabled={
								!pin || state === "waiting_touch" || state === "success"
							}
							className="btn-primary"
						>
							Authenticate
						</button>
					</>
				)}
			</GlassCard>
		</div>
	);
}
