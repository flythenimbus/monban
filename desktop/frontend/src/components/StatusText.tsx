import { cn } from "../util/cn";

interface StatusTextProps {
	children: string;
	variant?: "default" | "accent" | "success";
	pulse?: boolean;
}

export function StatusText({
	children,
	variant = "default",
	pulse = false,
}: StatusTextProps) {
	return (
		<div
			aria-live="polite"
			className={cn(
				"text-center text-sm",
				variant === "accent" || variant === "success"
					? "text-accent"
					: "text-text-secondary",
				variant === "success" && "font-medium",
				pulse && "animate-pulse motion-reduce:animate-none",
			)}
		>
			{children}
		</div>
	);
}
