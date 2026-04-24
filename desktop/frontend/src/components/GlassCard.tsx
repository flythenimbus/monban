import type { CSSProperties, ReactNode } from "react";
import { cn } from "../util/cn";

interface GlassCardProps {
	children: ReactNode;
	className?: string;
	style?: CSSProperties;
}

export function GlassCard({ children, className, style }: GlassCardProps) {
	return (
		<div
			className={cn(
				"glass rounded-2xl p-8 w-full max-w-[320px] space-y-5",
				className,
			)}
			style={style}
		>
			{children}
		</div>
	);
}
