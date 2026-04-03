// Maps raw Go error messages to user-friendly strings.
const errorMap: [RegExp, string][] = [
	[/pin invalid/i, "Incorrect PIN"],
	[/pin required/i, "PIN is required for this security key"],
	[
		/pin auth blocked/i,
		"PIN is blocked. Too many failed attempts. Reset your security key to continue.",
	],
	[
		/pin policy violation/i,
		"PIN does not meet requirements (too short or too simple)",
	],
	[
		/no FIDO2 device found/i,
		"Security key not detected. Make sure it's plugged in.",
	],
	[/device removed/i, "Security key was removed. Reinsert and try again."],
	[/user presence required/i, "Touch your security key to confirm"],
	[/operation denied/i, "Operation was denied. Please try again."],
	[/action timeout/i, "Timed out waiting for security key. Please try again."],
	[/no credentials/i, "Unauthorized key"],
	[
		/does not support hmac-secret/i,
		"This security key doesn't support hmac-secret. A compatible FIDO2 key is required.",
	],
	[
		/failed to set hmac salt/i,
		"Credentials are invalid or corrupted. Re-register your security key.",
	],
	[/could not unwrap master secret/i, "Unauthorized key"],
	[/insufficient disk space/i, "Not enough disk space"],
	[/already protected/i, "This path is already protected"],
	[/must be unlocked/i, "Unlock first before making changes"],
	[
		/cannot remove the last/i,
		"Can't remove your only key. Add another one first.",
	],
	[
		/applying secure settings/i,
		"Could not save settings. Check that Monban has the required permissions.",
	],
	[
		/config not found/i,
		"No configuration found. Register a security key first.",
	],
	[/folder not found/i, "Path not found. Please check the path and try again."],
	[/file not found/i, "Path not found. Please check the path and try again."],
	[
		/no such file or directory/i,
		"Path not found. Please check the path and try again.",
	],
];

export function friendlyError(err: unknown): string {
	const raw = extractMessage(err);
	for (const [pattern, friendly] of errorMap) {
		if (pattern.test(raw)) return friendly;
	}
	// Fallback: strip Go error chain prefixes like "registration failed: MakeCredential: "
	const parts = raw.split(": ");
	return parts[parts.length - 1] || raw;
}

function extractMessage(err: unknown): string {
	if (!err) return "Unknown error";
	if (typeof err === "string") return err;
	if (typeof err === "object") {
		const e = err as Record<string, unknown>;
		if (typeof e.message === "string") return e.message;
		if (typeof e.error === "string") return e.error;
	}
	return String(err);
}
