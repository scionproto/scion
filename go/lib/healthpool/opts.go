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

package healthpool

import "time"

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

func (opts PoolOptions) algorithm(p *Pool) func() (Info, error) {
	switch opts.Algorithm {
	case "", MinFailCount:
		return p.chooseMinFails
	default:
		return nil
	}
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
