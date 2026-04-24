import { useEffect, useRef, useState } from "react";
import { cn } from "../util/cn";
import { Button } from "./Button";
import { Input } from "./Input";
import { Spinner } from "./icons/Spinner";
import { Times } from "./icons/Times";

interface PinAuthProps {
	label?: string;
	onSubmit: (pin: string) => Promise<void>;
	onCancel: () => void;
	topGap?: boolean;
}

type Phase = "idle" | "touch" | "processing";

// Heuristic: after this long in the touch state, assume the user has
// tapped and the backend is doing post-assertion work (e.g. running
// install_pkg). Switching the affordance from "Touch..." to a spinner
// stops the UI looking frozen during that gap.
const TOUCH_TO_PROCESSING_MS = 1500;

export function PinAuth({
	label = "Authenticate with your security key to apply",
	onSubmit,
	onCancel,
	topGap = false,
}: PinAuthProps) {
	const [pin, setPin] = useState("");
	const [phase, setPhase] = useState<Phase>("idle");
	const inputRef = useRef<HTMLInputElement>(null);
	const busy = phase !== "idle";

	useEffect(() => {
		const handler = (e: KeyboardEvent) => {
			if (e.key === "Escape" && !busy) onCancel();
		};
		window.addEventListener("keydown", handler);
		return () => window.removeEventListener("keydown", handler);
	}, [busy, onCancel]);

	useEffect(() => {
		if (phase !== "touch") return;
		const id = setTimeout(() => setPhase("processing"), TOUCH_TO_PROCESSING_MS);
		return () => clearTimeout(id);
	}, [phase]);

	const handleSubmit = async () => {
		if (!pin) return;
		setPhase("touch");
		try {
			await onSubmit(pin);
		} finally {
			setPin("");
			setPhase("idle");
		}
	};

	return (
		<div
			className={cn(
				"glass overflow-hidden rounded-b-xl",
				topGap && "rounded-xl mt-3",
			)}
		>
			<div className="px-4 py-3 bg-accent/5">
				<div className="text-xs text-text-secondary mb-2">{label}</div>
				{phase === "touch" ? (
					<div className="text-xs text-accent animate-pulse motion-reduce:animate-none">
						Touch your security key...
					</div>
				) : phase === "processing" ? (
					<div className="text-xs text-accent flex items-center gap-2 [&_svg]:size-3.5">
						<Spinner />
						<span>Working...</span>
					</div>
				) : (
					<div className="flex items-center gap-2">
						<Input
							ref={inputRef}
							type="password"
							label="PIN"
							placeholder="Security key PIN"
							value={pin}
							onChange={(e) => setPin(e.target.value)}
							onKeyDown={(e) => e.key === "Enter" && pin && handleSubmit()}
							className="flex-1 !py-1.5 !px-2.5 !text-xs"
						/>
						<Button size="sm" onClick={handleSubmit} disabled={!pin}>
							Authenticate
						</Button>
						<button
							type="button"
							onClick={onCancel}
							aria-label="Cancel"
							className="text-text-secondary hover:text-text transition-colors cursor-pointer [&_svg]:size-4"
						>
							<Times />
						</button>
					</div>
				)}
			</div>
		</div>
	);
}
