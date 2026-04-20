package plugin

// Fire sends a lifecycle notify to every plugin subscribed to the given
// event. Plugin subscriptions come from the manifest's hooks list. This is
// a best-effort fire-and-forget; errors are logged but not returned.
//
// P1 supports only on:app_started and on:app_shutdown. Other events must
// still pass through without error for forward compatibility — plugins can
// subscribe to them but they simply won't fire yet.
func (h *Host) Fire(event string, payload any) {
	h.mu.Lock()
	targets := make([]*Plugin, 0, len(h.plugins))
	for _, p := range h.plugins {
		if subscribed(p.Manifest.Hooks, event) {
			targets = append(targets, p)
		}
	}
	h.mu.Unlock()

	for _, p := range targets {
		if err := p.notify(event, payload); err != nil {
			h.log.Printf("plugin[%s]: fire %s: %v", p.Manifest.Name, event, err)
		}
	}
}

func subscribed(hooks []string, event string) bool {
	for _, h := range hooks {
		if h == event {
			return true
		}
	}
	return false
}
