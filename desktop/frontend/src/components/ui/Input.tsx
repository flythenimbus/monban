import { type InputHTMLAttributes } from "react";

interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "className"> {
  label: string;
  className?: string;
}

export function Input({ label, className = "", ...props }: InputProps) {
  return (
    <input
      aria-label={label}
      className={`input-glass ${className}`}
      {...props}
    />
  );
}
