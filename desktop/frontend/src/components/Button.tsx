import type { ButtonHTMLAttributes } from "react";
import { cn } from "../util/cn";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
	variant?: "primary" | "secondary" | "danger";
	size?: "default" | "sm";
	fullWidth?: boolean;
}

export function Button({
	variant = "primary",
	size = "default",
	fullWidth = true,
	className,
	type = "button",
	...props
}: ButtonProps) {
	return (
		<button
			type={type}
			className={cn(
				`btn-${variant}`,
				size === "sm" && "w-auto! px-2.5 py-1.5 !text-xs !rounded-md",
				!fullWidth && size !== "sm" && "w-auto!",
				className,
			)}
			{...props}
		/>
	);
}
