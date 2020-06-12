// Copyright 2020 Anapaya Systems
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

package cppki_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
)

func TestValidityContains(t *testing.T) {
	now := time.Now()
	validity := cppki.Validity{
		NotBefore: now,
		NotAfter:  now.Add(time.Minute),
	}
	tests := map[string]struct {
		Time      time.Time
		Contained bool
	}{
		"Before": {
			Time: now.Add(-time.Minute),
		},
		"Same as NotBefore": {
			Time:      now,
			Contained: true,
		},
		"Between NotBefore and NotAfter": {
			Time:      now.Add(30 * time.Second),
			Contained: true,
		},
		"Same as NotAfter": {
			Time:      now.Add(time.Minute),
			Contained: true,
		},
		"After": {
			Time: now.Add(time.Hour),
		},
	}
	for name, test := range tests {
		assert.Equal(t, test.Contained, validity.Contains(test.Time), name)
	}
}

func TestValidityCovers(t *testing.T) {
	now := time.Now()
	validity := cppki.Validity{
		NotBefore: now,
		NotAfter:  now.Add(time.Minute),
	}
	tests := map[string]struct {
		DiffNotBefore time.Duration
		DiffNotAfter  time.Duration
		Covers        bool
	}{
		"Equal": {
			Covers: true,
		},
		"strict subset": {
			DiffNotBefore: time.Second,
			DiffNotAfter:  -time.Second,
			Covers:        true,
		},
		"NotBefore before": {
			DiffNotBefore: -time.Second,
		},
		"NotAfter after": {
			DiffNotAfter: time.Second,
		},
	}
	for name, test := range tests {
		other := cppki.Validity{
			NotBefore: validity.NotBefore.Add(test.DiffNotBefore),
			NotAfter:  validity.NotAfter.Add(test.DiffNotAfter),
		}
		assert.Equal(t, test.Covers, validity.Covers(other), name)
	}
}
