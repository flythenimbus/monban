import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "../util/cn";

interface InputProps
	extends Omit<InputHTMLAttributes<HTMLInputElement>, "className"> {
	label: string;
	className?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
	{ label, className, ...props },
	ref,
) {
	return (
		<input
			ref={ref}
			aria-label={label}
			className={cn("input-glass", className)}
			{...props}
		/>
	);
});
