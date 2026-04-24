import { cn } from "../util/cn";

interface SelectOption {
	value: string;
	label: string;
}

interface SelectProps {
	value: string;
	onChange: (value: string) => void;
	options: SelectOption[];
	label: string;
	disabled?: boolean;
}

export function Select({
	value,
	onChange,
	options,
	label,
	disabled,
}: SelectProps) {
	return (
		<select
			aria-label={label}
			title={label}
			value={value}
			onChange={(e) => onChange(e.target.value)}
			disabled={disabled}
			className={cn(
				"text-xs font-medium text-text bg-black/5 dark:bg-white/10 rounded-lg px-2.5 py-1.5 border-0 outline-none focus-visible:ring-2 focus-visible:ring-accent appearance-none",
				disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer",
			)}
		>
			{options.map((opt) => (
				<option key={opt.value} value={opt.value}>
					{opt.label}
				</option>
			))}
		</select>
	);
}
