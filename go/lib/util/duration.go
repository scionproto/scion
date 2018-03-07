// Copyright 2013 The Prometheus Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"regexp"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/common"
)

// This code is lightly adapted from
// https://github.com/prometheus/common/blob/2e54d0b93cba2fd133edc32211dcc32c06ef72ca/model/time.go#L182

var durationRE = regexp.MustCompile("^([0-9]+)(y|w|d|h|m|s|ms|us|µs|ns)$")

// ParseDuration parses a string into a time.Duration, assuming that a year
// always has 365d, a week always has 7d, and a day always has 24h.
//
// It is similar to time.ParseDuration, but differs in the following ways:
// - It adds support for the following units: "y", "w", "d"
// - It requires a unit suffix
// - It does not support mixed unit durations (e.g. `1h10m10s` is not supported).
// - It does not support negative durations.
func ParseDuration(durationStr string) (time.Duration, error) {
	matches := durationRE.FindStringSubmatch(durationStr)
	if len(matches) != 3 {
		return 0, common.NewBasicError("Invalid duration string", nil, "val", durationStr)
	}
	var (
		n, _ = strconv.Atoi(matches[1])
		dur  = time.Duration(n)
	)
	switch unit := matches[2]; unit {
	case "y":
		dur *= time.Hour * 24 * 365
	case "w":
		dur *= time.Hour * 24 * 7
	case "d":
		dur *= time.Hour * 24
	case "h":
		dur *= time.Hour
	case "m":
		dur *= time.Minute
	case "s":
		dur *= time.Second
	case "ms":
		dur *= time.Millisecond
	case "us", "µs":
		dur *= time.Microsecond
	case "ns":
		// Value already correct
	default:
		return 0, common.NewBasicError("Invalid time unit in duration string", nil,
			"unit", unit, "val", durationStr)
	}
	return dur, nil
}
