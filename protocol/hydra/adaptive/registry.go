package adaptive

import "sync"

// The registry lets host code look up adaptive-coordinator state by outbound
// tag without owning the outbound. Adaptive outbounds register their
// coordinator on construction and unregister on Close. Only getters are
// stored; each snapshot is copied out under the registry lock, and the
// getter itself serializes on the coordinator's own mutex, so no state is
// shared unlocked.
var (
	registryMu sync.RWMutex
	registry   = make(map[string]func() Snapshot)
)

// RegisterOutbound maps tag to get for SnapshotByTag. A nil getter is
// ignored; a later registration for the same tag replaces the earlier one.
func RegisterOutbound(tag string, get func() Snapshot) {
	if get == nil {
		return
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[tag] = get
}

// UnregisterOutbound drops tag. Unknown tags are ignored, so Close stays
// idempotent.
func UnregisterOutbound(tag string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(registry, tag)
}

// SnapshotByTag returns the current Coordinator snapshot registered under
// tag. ok is false when no outbound is registered under tag.
func SnapshotByTag(tag string) (Snapshot, bool) {
	registryMu.RLock()
	get, ok := registry[tag]
	registryMu.RUnlock()
	if !ok {
		return Snapshot{}, false
	}
	return get(), true
}
