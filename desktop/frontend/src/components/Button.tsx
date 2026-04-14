import type { ButtonHTMLAttributes } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
	variant?: "primary" | "secondary" | "danger";
	size?: "default" | "sm";
	fullWidth?: boolean;
}

export function Button({
	variant = "primary",
	size = "default",
	fullWidth = true,
	className = "",
	type = "button",
	...props
}: ButtonProps) {
	const base = `btn-${variant}`;
	const sizeClass =
		size === "sm" ? "w-auto! px-2.5 py-1.5 !text-xs !rounded-md" : "";
	const widthClass = !fullWidth && size !== "sm" ? "w-auto!" : "";

	return (
		<button
			type={type}
			className={`${base} ${sizeClass} ${widthClass} ${className}`.trim()}
			{...props}
		/>
	);
}
