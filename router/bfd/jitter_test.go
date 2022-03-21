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

package bfd_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/pkg/router/bfd"
	"github.com/scionproto/scion/go/pkg/router/bfd/mock_bfd"
)

func TestComputeInterval(t *testing.T) {
	t.Run("invalid inputs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		// controller is shared between test cases, and clean-up runs once at the end,
		// but it's fine here.
		defer ctrl.Finish()

		mockIntervalGenerator := mock_bfd.NewMockIntervalGenerator(ctrl)
		testCases := []*struct {
			transmitInterval time.Duration
			detectMult       uint
		}{
			{transmitInterval: -4, detectMult: 2},
			{transmitInterval: 0, detectMult: 4},
			{transmitInterval: 5 * time.Microsecond, detectMult: 0},
		}

		for _, tc := range testCases {
			assert.Panics(
				t,
				func() {
					bfd.ComputeInterval(tc.transmitInterval, tc.detectMult, mockIntervalGenerator)
				},
			)
		}
	})

	t.Run("valid inputs, nil generator", func(t *testing.T) {
		// check that not initializing the source does not panic
		assert.NotPanics(t, func() { bfd.ComputeInterval(10, 20, nil) })
	})

	t.Run("valid inputs", func(t *testing.T) {
		testCases := []*struct {
			generatorSetup   func(*mock_bfd.MockIntervalGenerator)
			transmitInterval time.Duration
			detectMult       uint
			expectedInterval time.Duration
		}{
			{
				generatorSetup: func(m *mock_bfd.MockIntervalGenerator) {
					m.EXPECT().Generate(bfd.MinJitter, bfd.MaxJitter).
						Return(0).AnyTimes()
				},
				transmitInterval: 100 * time.Microsecond,
				detectMult:       2,
				expectedInterval: 100 * time.Microsecond,
			},
			{
				generatorSetup: func(m *mock_bfd.MockIntervalGenerator) {
					m.EXPECT().Generate(bfd.MinJitter, bfd.MaxJitter).
						Return(10).AnyTimes()
				},
				transmitInterval: 100 * time.Microsecond,
				detectMult:       2,
				expectedInterval: 90 * time.Microsecond,
			},
			{
				generatorSetup: func(m *mock_bfd.MockIntervalGenerator) {
					m.EXPECT().Generate(bfd.MinJitter, bfd.MaxJitter).
						Return(bfd.MaxJitter).AnyTimes()
				},
				transmitInterval: 100 * time.Microsecond,
				detectMult:       2,
				expectedInterval: 75 * time.Microsecond,
			},
			{
				generatorSetup: func(m *mock_bfd.MockIntervalGenerator) {
					m.EXPECT().Generate(bfd.MinJitterDetectMult1, bfd.MaxJitter).
						Return(bfd.MinJitterDetectMult1).AnyTimes()
				},
				transmitInterval: 100 * time.Microsecond,
				detectMult:       1,
				expectedInterval: 90 * time.Microsecond,
			},
			{
				generatorSetup: func(m *mock_bfd.MockIntervalGenerator) {
					m.EXPECT().Generate(bfd.MinJitterDetectMult1, bfd.MaxJitter).
						Return(bfd.MaxJitter).AnyTimes()
				},
				transmitInterval: 100 * time.Microsecond,
				detectMult:       1,
				expectedInterval: 75 * time.Microsecond,
			},
		}

		for i, tc := range testCases {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockGenerator := mock_bfd.NewMockIntervalGenerator(ctrl)
			tc.generatorSetup(mockGenerator)
			assert.Equal(
				t,
				tc.expectedInterval,
				bfd.ComputeInterval(tc.transmitInterval, tc.detectMult, mockGenerator),
				fmt.Sprintf("test case %d (%+v)", i, tc),
			)
		}
	})
}

func TestGenerate(t *testing.T) {
	t.Run("invalid inputs", func(t *testing.T) {
		testCases := []*struct {
			x int
			y int
		}{
			{x: 10, y: 5},
			{x: -10, y: 5},
			{x: -10, y: -5},
			{x: 10, y: 10},
		}
		for _, tc := range testCases {
			intervalGenerator := bfd.DefaultIntervalGenerator{}
			assert.Panics(t, func() { intervalGenerator.Generate(tc.x, tc.y) })
		}
	})

	t.Run("valid inputs, default source", func(t *testing.T) {
		// check that not initializing the source does not panic
		intervalGenerator := bfd.DefaultIntervalGenerator{}
		assert.NotPanics(t, func() { intervalGenerator.Generate(10, 20) })
	})

	t.Run("valid inputs, custom source", func(t *testing.T) {
		testCases := []*struct {
			offset   int // 0 <= offset < (max - min)
			x        int
			y        int
			expected int
		}{
			{offset: 2, x: 4, y: 8, expected: 6},
			{offset: 3, x: 4, y: 8, expected: 7},
			{offset: 0, x: 4, y: 5, expected: 4},
			{offset: 3, x: 4, y: 1000, expected: 7},
		}

		for _, tc := range testCases {
			if tc.offset < 0 {
				panic(fmt.Sprintf("bad test data, %d < 0", tc.offset))
			}
			if tc.offset >= tc.y-tc.x {
				panic(fmt.Sprintf("bad test data, %d >= (%d - %d)", tc.offset, tc.y, tc.x))
			}
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockSource := mock_bfd.NewMockSource(ctrl)
			mockSource.EXPECT().Intn(gomock.Any()).Return(tc.offset).AnyTimes()

			intervalGenerator := bfd.DefaultIntervalGenerator{
				Source: mockSource,
			}
			assert.Equal(t, tc.expected, intervalGenerator.Generate(tc.x, tc.y))
		}
	})
}
