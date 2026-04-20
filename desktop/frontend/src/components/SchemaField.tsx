import type { PluginSettingSpec } from "../types";
import { Input } from "./Input";
import { Toggle } from "./Toggle";

interface SchemaFieldProps {
	fieldKey: string;
	spec: PluginSettingSpec;
	value: unknown;
	onChange: (v: unknown) => void;
}

/**
 * Auto-renders a single form field from a plugin's manifest-declared
 * settings schema. Supported types: bool, int, string, url. Unknown types
 * fall back to a text input so forward-compatibility doesn't break the UI.
 */
export function SchemaField({
	fieldKey,
	spec,
	value,
	onChange,
}: SchemaFieldProps) {
	const label = spec.label ?? fieldKey;

	if (spec.type === "bool") {
		return (
			<div className="flex items-center justify-between">
				<div className="pr-4">
					<div className="text-sm text-text">{label}</div>
					{spec.description && (
						<div className="text-xs text-text-secondary">
							{spec.description}
						</div>
					)}
				</div>
				<Toggle
					checked={Boolean(value)}
					onChange={() => onChange(!value)}
					label={label}
				/>
			</div>
		);
	}

	if (spec.type === "int") {
		return (
			<div>
				<Input
					type="number"
					label={label}
					value={value == null ? "" : String(value)}
					onChange={(e) => {
						const n = Number(e.target.value);
						onChange(Number.isFinite(n) ? n : 0);
					}}
					className="w-full"
				/>
				{spec.description && (
					<div className="text-xs text-text-secondary mt-1">
						{spec.description}
					</div>
				)}
			</div>
		);
	}

	const stringVal =
		typeof value === "string" ? value : value == null ? "" : String(value);

	return (
		<div>
			<Input
				type={spec.type === "url" ? "url" : "text"}
				label={label}
				value={stringVal}
				onChange={(e) => onChange(e.target.value)}
				className="w-full"
			/>
			{spec.description && (
				<div className="text-xs text-text-secondary mt-1">
					{spec.description}
				</div>
			)}
		</div>
	);
}
