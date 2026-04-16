package app

import (
	"log"
	"time"

	"monban/internal/monban"
)

// StartDeviceWatcher polls for security key presence and counter file integrity,
// locking vaults if either the key is removed or the counter file is deleted.
func (a *App) StartDeviceWatcher() {
	const missThreshold = 2 // require 2 consecutive misses to avoid USB glitches
	misses := 0

	go func() {
		for {
			time.Sleep(2 * time.Second)

			if a.IsLocked() {
				misses = 0
				continue
			}

			triggerLock := false
			reason := ""

			// Check security key presence
			connected, err := monban.DetectDevice()
			if err != nil || !connected {
				misses++
				if misses >= missThreshold {
					triggerLock = true
					reason = "security key removed"
				}
			} else {
				misses = 0
			}

			// Check counter file integrity
			if !triggerLock && !monban.CounterFileExists() {
				triggerLock = true
				reason = "counter file deleted"
			}

			if triggerLock {
				log.Printf("monban: %s, locking vaults...", reason)
				if err := a.Lock(); err != nil {
					log.Printf("monban: error locking: %v", err)
				}
				a.EnterFullscreen()
				if a.window != nil {
					a.window.EmitEvent("app:locked")
				}
				misses = 0
			}
		}
	}()
}
