import { forwardRef, type InputHTMLAttributes } from "react";

interface InputProps
	extends Omit<InputHTMLAttributes<HTMLInputElement>, "className"> {
	label: string;
	className?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
	{ label, className = "", ...props },
	ref,
) {
	return (
		<input
			ref={ref}
			aria-label={label}
			className={`input-glass ${className}`}
			{...props}
		/>
	);
});
