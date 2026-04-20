import { Events } from "@wailsio/runtime";
import { useEffect, useState } from "react";
import { api } from "../api";
import { friendlyError } from "../util/errors";
import { PinAuth } from "./PinAuth";

interface PinTouchRequest {
	id: string;
	title: string;
	subtitle: string;
}

/**
 * Mounted once at the app root. Listens for `plugin:pin-touch-request`
 * events from the Go host (emitted when a plugin calls the
 * request_pin_touch RPC) and pops a PinAuth dialog. User's PIN flows
 * back through api.respondPluginPinTouch → FIDO2 assert → plugin reply.
 *
 * Shown on top of whatever view is currently active so sudo from a
 * terminal produces a visible prompt even if the user hasn't unlocked
 * Monban recently.
 */
export function PluginPinTouchOverlay() {
	const [req, setReq] = useState<PinTouchRequest | null>(null);
	const [error, setError] = useState("");

	useEffect(() => {
		const offRequest = Events.On(
			"plugin:pin-touch-request",
			(event: { data: PinTouchRequest }) => {
				setReq(event.data);
				setError("");
			},
		);
		const offCancelled = Events.On(
			"plugin:pin-touch-cancelled",
			(event: { data: { id: string } }) => {
				setReq((current) => (current?.id === event.data.id ? null : current));
			},
		);
		return () => {
			offRequest();
			offCancelled();
		};
	}, []);

	if (!req) return null;

	return (
		<>
			{error && (
				<div className="fixed inset-x-3 bottom-24 z-50 glass rounded-xl px-4 py-2 text-sm text-red-500">
					{error}
				</div>
			)}
			<PinAuth
				label={req.title || "Authenticate with your security key"}
				onSubmit={async (pin: string) => {
					setError("");
					try {
						await api.respondPluginPinTouch(req.id, pin);
						setReq(null);
					} catch (err: unknown) {
						setError(friendlyError(err));
					}
				}}
				onCancel={() => {
					api.cancelPluginPinTouch(req.id).catch(() => {});
					setReq(null);
				}}
			/>
		</>
	);
}
