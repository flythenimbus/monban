import { type ReactNode } from "react";

interface AlertProps {
  children: ReactNode;
  onDismiss?: () => void;
}

export function Alert({ children, onDismiss }: AlertProps) {
  if (onDismiss) {
    return (
      <div role="alert" className="glass rounded-lg px-4 py-2.5 flex items-center justify-between border-error/20 border">
        <span className="text-error text-sm">{children}</span>
        <button onClick={onDismiss} aria-label="Dismiss error" className="text-text-secondary hover:text-text ml-2">&times;</button>
      </div>
    );
  }

  return (
    <div role="alert" className="bg-error/8 border border-error/20 rounded-lg px-4 py-2.5 text-center">
      <p className="text-error text-sm">{children}</p>
    </div>
  );
}
