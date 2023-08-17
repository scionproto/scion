// Copyright 2023 ETH Zurich
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

package drkeyutil

import (
	"os"
	"time"

	"github.com/scionproto/scion/pkg/private/util"
)

const (
	// DefaultEpochDuration is the default duration for the drkey SecretValue and derived keys
	DefaultEpochDuration   = 24 * time.Hour
	DefaultPrefetchEntries = 10000
	EnvVarEpochDuration    = "SCION_TESTING_DRKEY_EPOCH_DURATION"
	// DefaultAcceptanceWindowLength is the time width for accepting incoming packets. The
	// acceptance widown is then compute as:
	// aw := [T-a, T+a)
	// where aw:= acceptance window, T := time instant and a := acceptanceWindowOffset
	//
	// Picking the value equal or shorter than half of the drkey Grace Period ensures
	// that we accept packets for active keys only.
	DefaultAcceptanceWindowLength = 5 * time.Minute
	EnvVarAccpetanceWindow        = "SCION_TESTING_ACCEPTANCE_WINDOW"
)

func LoadEpochDuration() time.Duration {
	s := os.Getenv(EnvVarEpochDuration)
	if s == "" {
		return DefaultEpochDuration
	}
	duration, err := util.ParseDuration(s)
	if err != nil {
		return DefaultEpochDuration
	}
	return duration
}

func LoadAcceptanceWindow() time.Duration {
	s := os.Getenv(EnvVarAccpetanceWindow)
	if s == "" {
		return DefaultAcceptanceWindowLength
	}
	duration, err := util.ParseDuration(s)
	if err != nil {
		return DefaultAcceptanceWindowLength
	}
	return duration
}
