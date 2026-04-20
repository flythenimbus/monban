import { useEffect, useRef } from "react";
import * as App from "../../bindings/monban/internal/app/app";

const WIDTH = 420;
const TITLEBAR = 50;
const PADDING = 40;
const ANIM_DURATION_MS = 180;
const TOLERANCE_PX = 2;

/**
 * Watches the ref'd element for size changes and grows/shrinks the host
 * window to match — animated, not instant. Wails' native ResizeWindow
 * resizes the NSWindow in one step, which triggers a full webview
 * re-composite (backdrop-filter and gradient backgrounds re-render
 * against the new clip region). Splitting the jump into a tween of
 * small rAF steps makes each intermediate re-composite imperceptible.
 *
 * Minor observer fires (< TOLERANCE_PX) during the tween are ignored
 * so growing the window doesn't feedback-loop into retriggering the
 * tween on every reflow.
 */
export function useAutoResize() {
	const ref = useRef<HTMLDivElement>(null);

	useEffect(() => {
		if (!ref.current) return;

		let currentHeight = 0;
		let targetHeight = 0;
		let animHandle = 0;
		let animStart = 0;
		let animFrom = 0;

		const stepAnim = (now: number) => {
			const t = Math.min((now - animStart) / ANIM_DURATION_MS, 1);
			const eased = 1 - (1 - t) ** 3; // ease-out cubic
			const h = Math.round(animFrom + (targetHeight - animFrom) * eased);
			if (h !== currentHeight) {
				currentHeight = h;
				App.ResizeWindow(WIDTH, h);
			}
			if (t < 1) {
				animHandle = requestAnimationFrame(stepAnim);
			} else {
				animHandle = 0;
			}
		};

		const observer = new ResizeObserver((entries) => {
			for (const entry of entries) {
				const target = Math.ceil(entry.contentRect.height) + TITLEBAR + PADDING;
				const clamped = Math.max(200, Math.min(target, 800));
				// Ignore sub-pixel noise caused by our own tween reflowing.
				if (Math.abs(clamped - targetHeight) < TOLERANCE_PX) continue;
				targetHeight = clamped;

				if (currentHeight === 0) {
					currentHeight = clamped;
					App.ResizeWindow(WIDTH, clamped);
					continue;
				}

				animFrom = currentHeight;
				animStart = performance.now();
				if (!animHandle) {
					animHandle = requestAnimationFrame(stepAnim);
				}
			}
		});

		observer.observe(ref.current);
		return () => {
			observer.disconnect();
			if (animHandle) cancelAnimationFrame(animHandle);
		};
	}, []);

	return ref;
}
