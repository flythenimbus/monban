interface SelectOption {
  value: string;
  label: string;
}

interface SelectProps {
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  label: string;
}

export function Select({ value, onChange, options, label }: SelectProps) {
  return (
    <select
      aria-label={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="text-xs font-medium text-text bg-black/5 dark:bg-white/10 rounded-lg px-2.5 py-1.5 border-0 outline-none focus-visible:ring-2 focus-visible:ring-accent cursor-pointer appearance-none"
    >
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  );
}
