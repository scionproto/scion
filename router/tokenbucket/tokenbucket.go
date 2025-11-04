package tokenbucket

import (
	"sync"
	"time"
)

type TokenBucket struct {
	CurrentTokens   float64
	LastTimeApplied time.Time

	//Burst Size
	CBS float64

	//In bytes per second
	CIR float64

	// Lock
	lock sync.Mutex
}

// Initializes a new tockenbucket for the given burstSize and rate
func NewTokenBucket(initialTime time.Time, burstSize float64, rate float64) *TokenBucket {
	return &TokenBucket{
		CurrentTokens:   rate,
		CIR:             rate,
		CBS:             burstSize,
		LastTimeApplied: initialTime,
	}
}

// Sets a new rate for the token bucket
func (t *TokenBucket) SetRate(rate float64) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.CIR = rate
}

// Sets a new burst size for the token bucket
func (t *TokenBucket) SetBurstSize(burstSize float64) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.CBS = burstSize
}

// Apply calculates the current available tokens and checks whether there
// are enough tokens available. The success is indicated by a bool.
func (t *TokenBucket) Apply(size int, now time.Time) bool {
	t.lock.Lock()
	defer t.lock.Unlock()
	// Increase available tokens according to time passed since last call
	// Apply() is expected to be called from different threads
	// As a consequence, it is possible for now to be older than LastTimeApplied
	if !now.Before(t.LastTimeApplied) {
		t.CurrentTokens += now.Sub(t.LastTimeApplied).Seconds() * t.CIR
		t.CurrentTokens = min(t.CurrentTokens, t.CBS)
		t.LastTimeApplied = now
	}
	if t.CurrentTokens >= float64(size) {
		t.CurrentTokens -= float64(size)
		return true
	}
	return false
}

// This function calculates the minimal value of two float64.
func min(a float64, b float64) float64 {
	if a > b {
		return b
	} else {
		return a
	}
}
