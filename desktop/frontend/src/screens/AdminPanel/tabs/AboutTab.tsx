import { useAdmin } from "../AdminContext";
import { UpdateAlert } from "../components/UpdateAlert";

export function AboutTab() {
	const { setError: onError } = useAdmin();

	return (
		<div className="space-y-5">
			<UpdateAlert onError={onError} />
		</div>
	);
}
