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
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	year = time.Hour * 24 * 365
	week = time.Hour * 24 * 7
	day  = time.Hour * 24
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
		dur *= year
	case "w":
		dur *= week
	case "d":
		dur *= day
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

func FmtDuration(dur time.Duration) string {
	var (
		ns   = int64(dur)
		unit = "ns"
	)
	if ns == 0 {
		return "0s"
	}
	factors := map[string]int64{
		"y":  int64(time.Hour) * 24 * 365,
		"w":  int64(time.Hour) * 24 * 7,
		"d":  int64(time.Hour) * 24,
		"h":  int64(time.Hour),
		"m":  int64(time.Second) * 60,
		"s":  int64(time.Second),
		"ms": int64(time.Millisecond),
		"us": int64(time.Microsecond),
		"ns": int64(time.Nanosecond),
	}

	switch int64(0) {
	case ns % factors["y"]:
		unit = "y"
	case ns % factors["w"]:
		unit = "w"
	case ns % factors["d"]:
		unit = "d"
	case ns % factors["h"]:
		unit = "h"
	case ns % factors["m"]:
		unit = "m"
	case ns % factors["s"]:
		unit = "s"
	case ns % factors["ms"]:
		unit = "ms"
	case ns % factors["us"]:
		unit = "us"
	}
	return fmt.Sprintf("%d%s", ns/factors[unit], unit)
}
