import { type ReactNode, useRef, useState } from "react";
import { cn } from "../util/cn";

interface TabItem {
	key: string;
	label: string;
	content: ReactNode;
}

interface TabsProps {
	tabs: TabItem[];
	defaultTab?: string;
}

export function Tabs({ tabs, defaultTab }: TabsProps) {
	const keys = tabs.map((t) => t.key);
	const [active, setActive] = useState(defaultTab ?? keys[0]);
	const [slideDirection, setSlideDirection] = useState<"up" | "down" | null>(
		null,
	);
	const [animating, setAnimating] = useState(false);
	const prevTab = useRef(active);

	const switchTab = (next: string) => {
		if (next === active || animating) return;
		const dir = keys.indexOf(next) > keys.indexOf(active) ? "down" : "up";
		setSlideDirection(dir);
		setAnimating(true);
		setTimeout(() => {
			prevTab.current = active;
			setActive(next);
			setSlideDirection(dir === "down" ? "up" : "down");
			setTimeout(() => {
				setSlideDirection(null);
				setAnimating(false);
			}, 20);
		}, 150);
	};

	const activeTab = tabs.find((t) => t.key === active);

	return (
		<>
			<div role="tablist" className="flex gap-1 mb-5 glass rounded-xl p-1">
				{tabs.map((t) => (
					<button
						type="button"
						key={t.key}
						role="tab"
						aria-selected={t.key === active}
						onClick={() => switchTab(t.key)}
						className={cn(
							"flex-1 py-2 text-sm font-medium rounded-lg transition-all cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
							t.key === active
								? "bg-white/70 dark:bg-white/10 text-text shadow-sm"
								: "text-text-secondary hover:text-text",
						)}
					>
						{t.label}
					</button>
				))}
			</div>

			<div
				role="tabpanel"
				aria-label={activeTab?.label}
				className="transition-[opacity,transform] duration-150 ease-out motion-reduce:transition-none"
				style={{
					opacity: slideDirection ? 0 : 1,
					transform:
						slideDirection === "down"
							? "translateY(12px)"
							: slideDirection === "up"
								? "translateY(-12px)"
								: "translateY(0)",
				}}
			>
				{activeTab?.content}
			</div>
		</>
	);
}
