//go:build race

package dhcp

// raceEnabled skips timing tests: the race detector slows the engine several times over.
const raceEnabled = true
