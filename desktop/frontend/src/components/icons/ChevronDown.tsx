export function ChevronDown({ className = "w-4 h-4" }: { className?: string }) {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 20 20"
			fill="currentColor"
			className={className}
			aria-hidden="true"
		>
			<path
				fillRule="evenodd"
				d="M5.22 8.22a.75.75 0 011.06 0L10 11.94l3.72-3.72a.75.75 0 111.06 1.06l-4.25 4.25a.75.75 0 01-1.06 0L5.22 9.28a.75.75 0 010-1.06z"
				clipRule="evenodd"
			/>
		</svg>
	);
}
