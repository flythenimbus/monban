import { Browser } from "@wailsio/runtime";
import { useAdmin } from "../AdminContext";
import { UpdateAlert } from "../components/UpdateAlert";

export function AboutTab() {
	const { setError: onError } = useAdmin();

	return (
		<div className="space-y-5">
			<UpdateAlert onError={onError} />
			<div className="glass rounded-xl px-4 py-3 text-xs text-text-secondary text-center space-y-1">
				<div>
					Created by{" "}
					<button
						type="button"
						onClick={() => Browser.OpenURL("https://monban.app")}
						className="text-accent hover:text-accent/80 cursor-pointer font-medium"
					>
						flythenimbus
					</button>
				</div>
				<div>
					Licensed under{" "}
					<button
						type="button"
						onClick={() =>
							Browser.OpenURL("https://www.gnu.org/licenses/gpl-3.0.html")
						}
						className="text-accent hover:text-accent/80 cursor-pointer font-medium"
					>
						GPLv3
					</button>
				</div>
			</div>
		</div>
	);
}
