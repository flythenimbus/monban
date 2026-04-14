import { useState } from "react";
import { Input } from "./Input";
import { Times } from "./icons/Times";

interface PinAuthProps {
	label?: string;
	onSubmit: (pin: string) => Promise<void>;
	onCancel: () => void;
}

export function PinAuth({
	label = "Authenticate with your security key to apply",
	onSubmit,
	onCancel,
}: PinAuthProps) {
	const [pin, setPin] = useState("");
	const [waiting, setWaiting] = useState(false);

	const handleSubmit = async () => {
		if (!pin) return;
		setWaiting(true);
		try {
			await onSubmit(pin);
		} finally {
			setPin("");
			setWaiting(false);
		}
	};

	return (
		<div className="px-4 py-3 bg-accent/5">
			<div className="text-xs text-text-secondary mb-2">{label}</div>
			{waiting ? (
				<div className="text-xs text-accent animate-pulse">
					Touch your security key...
				</div>
			) : (
				<div className="flex items-center gap-2">
					<Input
						type="password"
						label="PIN"
						placeholder="Security key PIN"
						value={pin}
						onChange={(e) => setPin(e.target.value)}
						onKeyDown={(e) => e.key === "Enter" && pin && handleSubmit()}
						className="flex-1 !py-1.5 !px-2.5 !text-xs"
					/>
					<button
						type="button"
						onClick={handleSubmit}
						disabled={!pin}
						className="btn-primary w-auto! px-2.5 py-1.5 text-xs !text-xs !rounded-md"
					>
						Authenticate
					</button>
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
	);
}
