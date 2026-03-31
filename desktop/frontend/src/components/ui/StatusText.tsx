interface StatusTextProps {
  children: string;
  variant?: "default" | "accent" | "success";
  pulse?: boolean;
}

export function StatusText({ children, variant = "default", pulse = false }: StatusTextProps) {
  const color =
    variant === "accent" || variant === "success"
      ? "text-accent"
      : "text-text-secondary";

  const weight = variant === "success" ? "font-medium" : "";
  const animation = pulse ? "animate-pulse motion-reduce:animate-none" : "";

  return (
    <div aria-live="polite" className={`text-center text-sm ${color} ${weight} ${animation}`}>
      {children}
    </div>
  );
}
