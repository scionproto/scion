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

package control

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/topology"
)

const (
	envDisable = "SCION_EXPERIMENTAL_BFD_DISABLE"
	envMult    = "SCION_EXPERIMENTAL_BFD_DETECT_MULT"
	envMinTx   = "SCION_EXPERIMENTAL_BFD_DESIRED_MIN_TX"
	envMinRx   = "SCION_EXPERIMENTAL_BFD_REQUIRED_MIN_RX"
)

// BFD is the configuration for the BFD sessions.
type BFD topology.BFD

func withDefaults(cfg BFD) BFD {
	// If default is disable, BFD is globally disabled.
	if bfdDefaults.Disable {
		cfg.Disable = true
	}
	if cfg.DetectMult == 0 {
		cfg.DetectMult = bfdDefaults.DetectMult
	}
	if cfg.DesiredMinTxInterval == 0 {
		cfg.DesiredMinTxInterval = bfdDefaults.DesiredMinTxInterval
	}
	if cfg.RequiredMinRxInterval == 0 {
		cfg.RequiredMinRxInterval = bfdDefaults.RequiredMinRxInterval
	}
	return cfg
}

var (
	bfdDefaults = BFD{
		DetectMult:            3,
		DesiredMinTxInterval:  25 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
		// Disable indicates if BFD is disabled globally.
		Disable: false,
	}
)

func init() {
	if val := os.Getenv(envDisable); val != "" {
		if disabled, err := strconv.ParseBool(val); err == nil {
			bfdDefaults.Disable = disabled
			fmt.Fprintf(os.Stderr, "%s=%v\n", envDisable, disabled)
		} else {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", envDisable, err)
		}
	}
	if val := os.Getenv(envMult); val != "" {
		if p, err := strconv.ParseUint(val, 10, 8); err == nil {
			bfdDefaults.DetectMult = uint8(p)
			fmt.Fprintf(os.Stderr, "%s=%v\n", envMult, bfdDefaults.DetectMult)
		} else {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", envMult, err)
		}
	}
	if val := os.Getenv(envMinTx); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			bfdDefaults.DesiredMinTxInterval = d
			fmt.Fprintf(os.Stderr, "%s=%v\n", envMinTx, bfdDefaults.DesiredMinTxInterval)
		} else {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", envMinTx, err)
		}
	}
	if val := os.Getenv(envMinRx); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			bfdDefaults.RequiredMinRxInterval = d
			fmt.Fprintf(os.Stderr, "%s=%v\n", envMinRx, bfdDefaults.RequiredMinRxInterval)
		} else {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", envMinRx, err)
		}
	}
}
