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

	"github.com/scionproto/scion/private/topology"
)

const (
	envMult  = "SCION_EXPERIMENTAL_BFD_DETECT_MULT"
	envMinTx = "SCION_EXPERIMENTAL_BFD_DESIRED_MIN_TX"
	envMinRx = "SCION_EXPERIMENTAL_BFD_REQUIRED_MIN_RX"
)

// BFD is the configuration for the BFD sessions.
type BFD topology.BFD

// XXX(sgmonroy) note that env values only affect defaults, which in turn are only used
// if there were no BFD related settings in the topology.
func WithDefaults(cfg BFD) BFD {
	if cfg.DetectMult == 0 {
		cfg.DetectMult = BFDDefaults.DetectMult
	}
	if cfg.DesiredMinTxInterval == 0 {
		cfg.DesiredMinTxInterval = BFDDefaults.DesiredMinTxInterval
	}
	if cfg.RequiredMinRxInterval == 0 {
		cfg.RequiredMinRxInterval = BFDDefaults.RequiredMinRxInterval
	}
	return cfg
}

var (
	BFDDefaults = BFD{
		DetectMult:            3,
		DesiredMinTxInterval:  200 * time.Millisecond,
		RequiredMinRxInterval: 200 * time.Millisecond,
	}
)

func init() {
	if val := os.Getenv(envMult); val != "" {
		if p, err := strconv.ParseUint(val, 10, 8); err == nil {
			BFDDefaults.DetectMult = uint8(p)
			fmt.Fprintf(os.Stderr, "%s=%v\n", envMult, BFDDefaults.DetectMult)
		} else {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", envMult, err)
		}
	}
	if val := os.Getenv(envMinTx); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			BFDDefaults.DesiredMinTxInterval = d
			fmt.Fprintf(os.Stderr, "%s=%v\n", envMinTx, BFDDefaults.DesiredMinTxInterval)
		} else {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", envMinTx, err)
		}
	}
	if val := os.Getenv(envMinRx); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			BFDDefaults.RequiredMinRxInterval = d
			fmt.Fprintf(os.Stderr, "%s=%v\n", envMinRx, BFDDefaults.RequiredMinRxInterval)
		} else {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", envMinRx, err)
		}
	}
}
