// Copyright 2019 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package healthpool provides a generic way to keep track of the health
// infos for a set of keys.
//
// Usage
//
// This package is used to implement health pools for specific purposes.
// They can be found in the subpackages. Client packages should use these
// implementations, unless they implement their own specific health pool.
//
// Pool
//
// The pool keeps a map of all registered keys to their health info. It is
// used to choose the best info based on the fail count and the initialized
// selection algorithm. The behavior of the pool can be modified at
// initialization with the provided PoolOptions.
//
// The pool periodically reduces the fail count for every info that has not
// failed for a specified amount of time. The fail count is divided by two
// every expire interval starting from that point.
//
// Info
//
// The info keeps track of the failures for a given key. The client should
// call the Fail method to increase the fail count.
package healthpool

import "time"

// Info keeps track of the fails for a key.
type Info interface {
	// Fail increases the fail count.
	Fail()
	// FailCount returns the fail count.
	FailCount() int
	// ResetCount resets the fail count to zero.
	ResetCount()
	// expireFails reduces the fail count.
	expireFails(now time.Time, opts ExpireOptions)
}

// InfoKey is the key that identifies an entry.
type InfoKey string

// InfoMap maps the key to its health info.
type InfoMap map[InfoKey]Info

// Pool holds entries and their health. It allows to choose entries based
// on their health.
type Pool interface {
	// Update updates the info entries in the pool. Entries in the pool
	// that are not in infos are removed. Entries in infos that are not in
	// the pool are added. However, if Options.AllowEmpty is not set, and
	// the Update causes an empty pool, the entries are not replaced and an
	// error is returned.
	Update(infos InfoMap) error
	// Choose chooses info based on the configured algorithm.
	Choose() (Info, error)
	// Close closes the pool and stops the periodic fail expiration.
	// After the pool is closed, it can no longer be updated.
	Close()
}

// PoolOptions define the behavior of the pool.
type PoolOptions struct {
	// Algorithm is the choosing algorithm. In case of the empty string,
	// MinFailCount is used.
	Algorithm Algorithm
	// AllowEmpty indicates that the pool is allowed to be empty.
	AllowEmpty bool
	// Expire contains the expiration options.
	Expire ExpireOptions
}

func (opts PoolOptions) algorithm() Algorithm {
	if opts.Algorithm == "" {
		return MinFailCount
	}
	return opts.Algorithm
}

const (
	// MinFailCount selects a pool entry with the minimum fail count.
	MinFailCount Algorithm = "MinFailCount"
)

// Algorithm is the choosing algorithm of the pool.
type Algorithm string

const (
	// DefaultExpireStart is the the default for ExpireStart.
	DefaultExpireStart = 5 * time.Minute
	// DefaultExpireInterval is the default for ExpireInterval.
	DefaultExpireInterval = 10 * time.Second
)

// ExpireOptions define the expiration behavior.
type ExpireOptions struct {
	// Start is the time without failures for an info after which
	// exponential fail expiration starts. In case of the zero value, the
	// DefaultExpireStart is used.
	Start time.Duration
	// Interval is the time between exponential fail expirations.
	// In case of the zero value, the DefaultExpireInterval is used.
	Interval time.Duration
}

func (opts *ExpireOptions) start() time.Duration {
	return defaultDur(opts.Start, DefaultExpireStart)
}

func (opts *ExpireOptions) interval() time.Duration {
	return defaultDur(opts.Interval, DefaultExpireInterval)
}

func defaultDur(val, def time.Duration) time.Duration {
	if val == 0 {
		return def
	}
	return val
}
