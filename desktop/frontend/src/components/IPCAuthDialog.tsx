import { useState } from "react";
import { api } from "../api";
import { useAutoResize } from "../hooks/useAutoResize";
import { friendlyError } from "../util/errors";
import { Alert } from "./Alert";
import { Button } from "./Button";
import { Input } from "./Input";
import { StatusText } from "./StatusText";

interface IPCAuthDialogProps {
	service: string;
	user: string;
	onDone: () => void;
}

const serviceLabels: Record<string, string> = {
	authorization: "System authorization",
	sudo: "Sudo",
};

type AuthState = "idle" | "waiting_touch" | "error" | "success";

export function IPCAuthDialog({ service, user, onDone }: IPCAuthDialogProps) {
	const contentRef = useAutoResize();
	const [pin, setPin] = useState("");
	const [state, setState] = useState<AuthState>("idle");
	const [error, setError] = useState("");

	const label = serviceLabels[service] || service || "Authentication";

	const handleSubmit = async () => {
		if (!pin) return;
		setState("waiting_touch");
		setError("");
		try {
			await api.handleIPCAuth(pin);
			setState("success");
			setTimeout(onDone, 500);
		} catch (err: unknown) {
			setError(friendlyError(err));
			setState("error");
			setPin("");
		}
	};

	const handleCancel = () => {
		api.cancelIPCAuth();
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
						{label} requested
					</h1>
					<p className="text-text-secondary text-sm mt-1">
						{user ? `For user ${user} — ` : ""}Enter PIN and touch your
						security key
					</p>
				</div>

				{state === "error" && <Alert>{error}</Alert>}

				{state === "waiting_touch" ? (
					<StatusText variant="accent" pulse>
						Touch your security key...
					</StatusText>
				) : state === "success" ? (
					<StatusText variant="success">Authorized</StatusText>
				) : (
					<>
						<Input
							type="password"
							label="Security key PIN"
							placeholder="Security key PIN"
							value={pin}
							onChange={(e) => setPin(e.target.value)}
							onKeyDown={(e) => e.key === "Enter" && pin && handleSubmit()}
							autoFocus
						/>

						<div className="flex gap-2">
							<Button onClick={handleSubmit} disabled={!pin} className="flex-1">
								Authenticate
							</Button>
							<Button variant="secondary" onClick={handleCancel} className="flex-1">
								Cancel
							</Button>
						</div>
					</>
				)}
			</div>
		</div>
	);
}
