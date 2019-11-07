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

package spath

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExpTimeType(t *testing.T) {
	type TimeErrPair struct {
		ExpTime ExpTimeType
		Error   assert.ErrorAssertionFunc
	}
	tests := []struct {
		Name      string
		Duration  time.Duration
		RoundUp   TimeErrPair
		RoundDown TimeErrPair
		Rounded   bool
	}{
		{
			Name:     "Smaller than unit",
			Duration: 300 * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 0,
				Error:   assert.NoError,
			},
			RoundDown: TimeErrPair{
				Error: assert.Error,
			},
			Rounded: true,
		},
		{
			Name:     "Exactly the unit",
			Duration: ExpTimeUnit * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 0,
				Error:   assert.NoError,
			},
			RoundDown: TimeErrPair{
				ExpTime: 0,
				Error:   assert.NoError,
			},
		},
		{
			Name:     "Slightly larger than unit",
			Duration: 400 * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 1,
				Error:   assert.NoError,
			},
			RoundDown: TimeErrPair{
				ExpTime: 0,
				Error:   assert.NoError,
			},
			Rounded: true,
		},
		{
			Name:     "Slightly smaller than two units",
			Duration: 650 * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 1,
				Error:   assert.NoError,
			},
			RoundDown: TimeErrPair{
				ExpTime: 0,
				Error:   assert.NoError,
			},
			Rounded: true,
		},
		{
			Name:     "Exactly two units",
			Duration: 2 * ExpTimeUnit * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 1,
				Error:   assert.NoError,
			},
			RoundDown: TimeErrPair{
				ExpTime: 1,
				Error:   assert.NoError,
			},
		},
		{
			Name:     "Between units",
			Duration: 840 * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 2,
				Error:   assert.NoError,
			},
			RoundDown: TimeErrPair{
				ExpTime: 1,
				Error:   assert.NoError,
			},
			Rounded: true,
		},
		{
			Name:     "Maximum expiration time",
			Duration: (time.Duration(MaxTTLField) + 1) * ExpTimeUnit * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: MaxTTLField,
				Error:   assert.NoError,
			},
			RoundDown: TimeErrPair{
				ExpTime: MaxTTLField,
				Error:   assert.NoError,
			},
		},
		{
			Name:     "Larger than maximum relative expiration",
			Duration: 87000 * time.Second,
			RoundUp: TimeErrPair{
				Error: assert.Error,
			},
			RoundDown: TimeErrPair{
				ExpTime: MaxTTLField,
				Error:   assert.NoError,
			},
			Rounded: true,
		},
	}
	t.Run("Conversion from duration to relative expiration time should be correct",
		func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.Name, func(t *testing.T) {
					t.Run("Rounding up", func(t *testing.T) {
						expTime, err := ExpTimeFromDuration(test.Duration, true)
						test.RoundUp.Error(t, err)
						assert.Equal(t, test.RoundUp.ExpTime, expTime)
					})
					t.Run("Rounding down", func(t *testing.T) {
						expTime, err := ExpTimeFromDuration(test.Duration, false)
						test.RoundDown.Error(t, err)
						assert.Equal(t, test.RoundDown.ExpTime, expTime)
					})
				})
			}
		})
	t.Run("Conversion from relative expiration time to duration should be correct",
		func(t *testing.T) {
			for _, test := range tests {
				if !test.Rounded {
					t.Run(test.Name, func(t *testing.T) {
						assert.Equal(t, test.Duration, test.RoundUp.ExpTime.ToDuration())
					})
				}
			}
		})
}
