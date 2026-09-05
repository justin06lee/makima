//go:build !darwin && !linux

package supervise

// No service manager is driven on other platforms; daemons are started
// directly and last until the process exits or the machine restarts.
func platformManager(Daemon) (manager, bool) { return nil, false }
