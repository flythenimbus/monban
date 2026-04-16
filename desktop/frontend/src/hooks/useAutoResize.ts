import { useEffect, useRef } from "react";
import * as App from "../../bindings/monban/internal/app/app";

const WIDTH = 420;
const TITLEBAR = 50;
const PADDING = 40;

export function useAutoResize() {
	const ref = useRef<HTMLDivElement>(null);

	useEffect(() => {
		if (!ref.current) return;

		const observer = new ResizeObserver((entries) => {
			for (const entry of entries) {
				const contentHeight =
					Math.ceil(entry.contentRect.height) + TITLEBAR + PADDING;
				const clamped = Math.max(200, Math.min(contentHeight, 800));
				App.ResizeWindow(WIDTH, clamped);
			}
		});

		observer.observe(ref.current);
		return () => observer.disconnect();
	}, []);

	return ref;
}
