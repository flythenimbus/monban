interface LogoProps {
	className?: string;
}

export function Logo({ className = "w-24 h-24" }: LogoProps) {
	return (
		<picture>
			<source srcSet="/logo-light.png" media="(prefers-color-scheme: dark)" />
			<img src="/logo-dark.png" alt="Monban" className={className} />
		</picture>
	);
}
