import { type ReactNode, type CSSProperties } from "react";

interface GlassCardProps {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}

export function GlassCard({ children, className = "", style }: GlassCardProps) {
  return (
    <div className={`glass rounded-2xl p-8 w-full max-w-[320px] space-y-5 ${className}`} style={style}>
      {children}
    </div>
  );
}
