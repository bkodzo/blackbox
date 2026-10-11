//go:build race

package session

// slowdown scales time limits in tests: the race detector makes code
// several times slower.
const slowdown = 10
