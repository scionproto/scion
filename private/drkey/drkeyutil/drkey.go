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
	DefaultEpochDuration = 24 * time.Hour
	EnvVarEpochDuration  = "SCION_TESTING_DRKEY_EPOCH_DURATION"
	// DefaultAcceptanceWindow is the time width for accepting incoming packets. The
	// acceptance window is then computed as:
	// aw := [T-a, T+a)
	// where aw:= acceptance window, T := time instant and a := aw/2
	DefaultAcceptanceWindow = 5 * time.Minute
	EnvVarAcceptanceWindow  = "SCION_TESTING_ACCEPTANCE_WINDOW"
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
	s := os.Getenv(EnvVarAcceptanceWindow)
	if s == "" {
		return DefaultAcceptanceWindow
	}
	duration, err := util.ParseDuration(s)
	if err != nil {
		return DefaultAcceptanceWindow
	}
	return duration
}
