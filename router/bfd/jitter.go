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

package bfd

import (
	"fmt"
	"math/rand/v2"
	"time"
)

const (
	// minJitter is the minimum percentage that the interval between periodic
	// Control packets needs to be reduced by in cases where the local detection multiplier
	// is more than 1. This is defined in RFC 5880, Section 6.8.7.
	minJitter = 0
	// minJitterDetectMult1 is the minimum percentage that the interval between periodic
	// Control packets needs to be reduced by in cases where the local detection multiplier
	// is 1. This is defined in RFC 5880, Section 6.8.7.
	minJitterDetectMult1 = 10
	// maxJitter is the maximum percentage that the interval between periodic
	// Control packets needs to be reduced by. This is defined in RFC 5880, Section 6.8.7.
	maxJitter = 25
)

// computeInterval calculates the duration after which the next packet should be sent,
// depending on the transmission interval and detection multiplier of the local BFD
// session.
//
// The function panics if transmission interval <= 0, or if
// detection multiplier == 0.
//
// Argument gen is used to determine the random percentage that the interval between
// periodic BFD Control packets should be reduced by. If gen is nil, math/rand is used
// for randomness.
func computeInterval(transmitInterval time.Duration, detectMult uint,
	gen IntervalGenerator) time.Duration {

	if transmitInterval <= 0 {
		panic("transmission interval must be > 0")
	}
	if detectMult == 0 {
		panic("detection multiplier must be > 0")
	}
	jitter := minJitter
	if detectMult == 1 {
		jitter = minJitterDetectMult1
	}
	var jitterPercent int
	if gen != nil {
		jitterPercent = gen.Generate(jitter, maxJitter)
	} else {
		jitterPercent = defaultIntervalGenerator{}.Generate(jitter, maxJitter)
	}
	return (transmitInterval * time.Duration(100-jitterPercent)) / 100
}

// IntervalGenerator generates integers in [x, y). It panics if x < 0 or if y <= x.
type IntervalGenerator interface {
	Generate(x, y int) int
}

// defaultIntervalGenerator generates integers in a range based on
// an interface containing math/rand.Intn. This interface is satisfied
// standard Go library *math/rand.Rand.
//
// defaultIntervalGenerator is not suitable for cryptographic use.
type defaultIntervalGenerator struct {
	// Source is used for pseudorandomness. Implementations do
	// not need to be strong enough for use in cryptography. If nil,
	// the default random number generator in package rand is used.
	Source Source
}

// Generate returns pseudorandom integers from [x, y). Generate panics
// if x < 0 or y <= x.
//
// The generator is not safe for cryptographic use.
func (g defaultIntervalGenerator) Generate(x, y int) int {
	if x < 0 || y <= x {
		panic(fmt.Sprintf("bad integer range: [%d,%d)", x, y))
	}
	return g.intn(y-x) + x
}

func (g defaultIntervalGenerator) intn(n int) int {
	if g.Source == nil {
		return rand.IntN(n)
	}
	return g.Source.Intn(n)
}

// Source is an pseudorandom number generator interface that is
// satisfied by package math/rand's Rand type.
type Source interface {
	Intn(n int) int
}
