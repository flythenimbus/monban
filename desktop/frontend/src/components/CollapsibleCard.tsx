import type { ReactNode } from "react";
import { cn } from "../util/cn";
import { ChevronDown } from "./icons/ChevronDown";

interface CollapsibleCardProps {
	header: ReactNode;
	open: boolean;
	onToggle: () => void;
	children?: ReactNode;
	footer?: ReactNode;
}

/**
 * A glass-styled card with a clickable header that expands to reveal its
 * children. Used for any settings row that needs disclosure behaviour
 * (plugin entries, vault rows with details, etc.).
 *
 * `footer`, when set, renders flush at the bottom of the card with a
 * divider above it — used for inline auth prompts that should feel
 * attached to the card rather than floating below it.
 */
export function CollapsibleCard({
	header,
	open,
	onToggle,
	children,
	footer,
}: CollapsibleCardProps) {
	return (
		<div className="glass rounded-xl overflow-hidden">
			<button
				type="button"
				onClick={onToggle}
				aria-expanded={open}
				className="w-full text-left px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-black/5 dark:hover:bg-white/5 transition-colors"
			>
				<div className="min-w-0 flex-1">{header}</div>
				<span
					className={cn(
						"ml-3 text-text-secondary/60 transition-transform",
						open ? "rotate-0" : "-rotate-90",
					)}
				>
					<ChevronDown />
				</span>
			</button>
			{open && (
				<div className="px-4 py-3 border-t border-black/5 dark:border-white/5 space-y-3">
					{children}
				</div>
			)}
			{footer}
		</div>
	);
}
