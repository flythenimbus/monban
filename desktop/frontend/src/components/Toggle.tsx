interface ToggleProps {
	checked: boolean;
	onChange: () => void;
	label: string;
}

export function Toggle({ checked, onChange, label }: ToggleProps) {
	return (
		<button
			type="button"
			role="switch"
			aria-checked={checked}
			aria-label={label}
			onClick={onChange}
			className={`relative w-10 h-6 rounded-full transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
				checked ? "bg-accent" : "bg-black/10 dark:bg-white/15"
			}`}
		>
			<div
				className={`absolute top-0.5 w-5 h-5 rounded-full bg-white dark:bg-gray-200 shadow-sm transition-transform motion-reduce:transition-none ${
					checked ? "translate-x-[18px]" : "translate-x-0.5"
				}`}
			/>
		</button>
	);
}
