import { Alert, Tabs } from "../../components";
import { useAutoResize } from "../../hooks/useAutoResize";
import { AdminProvider, useAdmin } from "./AdminContext";
import { AboutTab } from "./tabs/AboutTab";
import { GeneralTab } from "./tabs/GeneralTab";
import { KeysTab } from "./tabs/KeysTab";

interface AdminPanelProps {
	rollbackWarning?: boolean;
	onDismissRollback?: () => void;
}

function AdminPanelInner({
	rollbackWarning,
	onDismissRollback,
}: AdminPanelProps) {
	const contentRef = useAutoResize();
	const { error, setError } = useAdmin();

	return (
		<div ref={contentRef} className="gradient-bg flex flex-col p-6 pt-14">
			<div className="flex items-center justify-between mb-5">
				<h1 className="text-lg font-semibold text-text">Monban</h1>
				<span className="text-accent text-xs font-medium px-2 py-1 rounded-full bg-accent/10">
					Unlocked
				</span>
			</div>

			{rollbackWarning && (
				<div className="mb-4">
					<Alert onDismiss={onDismissRollback}>
						Config rollback detected — your settings may have been restored from
						a backup or tampered with. Please verify your settings below.
					</Alert>
				</div>
			)}

			{error && (
				<div className="mb-4">
					<Alert onDismiss={() => setError("")}>{error}</Alert>
				</div>
			)}

			<Tabs
				tabs={[
					{
						key: "general",
						label: "General",
						content: <GeneralTab />,
					},
					{
						key: "keys",
						label: "Keys",
						content: <KeysTab />,
					},
					{
						key: "about",
						label: "About",
						content: <AboutTab />,
					},
				]}
			/>
		</div>
	);
}

export function AdminPanel({
	rollbackWarning,
	onDismissRollback,
}: AdminPanelProps) {
	return (
		<AdminProvider>
			<AdminPanelInner
				rollbackWarning={rollbackWarning}
				onDismissRollback={onDismissRollback}
			/>
		</AdminProvider>
	);
}
