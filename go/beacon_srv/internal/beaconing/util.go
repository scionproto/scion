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

package beaconing

import (
	"hash"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
)

// createHopF creates a hop field with the provided parameters. The previous hop
// field, if any, must contain all raw bytes including the flags.
func createHopF(inIfid, egIfid common.IFIDType, ts time.Time, prev common.RawBytes, cfg Config,
	mac hash.Hash) (*spath.HopField, error) {

	meta := cfg.Signer.Meta()
	diff := meta.ExpTime.Sub(ts)
	if diff < 1*time.Hour {
		log.Warn("Signer expiration time is near", "ts", ts,
			"chainExpiration", meta.ExpTime, "src", meta.Src)
	}
	expiry, err := spath.ExpTimeFromDuration(diff, false)
	if err != nil {
		min := ts.Add(spath.ExpTimeType(0).ToDuration())
		return nil, common.NewBasicError("Chain does not cover minimum hop expiration time", nil,
			"minimumExpiration", min, "chainExpiration", meta.ExpTime, "src", meta.Src)
	}
	if expiry > cfg.maxExpTime {
		expiry = cfg.maxExpTime
	}
	hop := &spath.HopField{
		ConsIngress: inIfid,
		ConsEgress:  egIfid,
		ExpTime:     expiry,
	}
	if prev != nil {
		// Do not include the flags of the hop field in the mac input.
		prev = prev[1:]
	}
	if hop.Mac, err = hop.CalcMac(mac, util.TimeToSecs(ts), prev); err != nil {
		return nil, common.NewBasicError("Unable to create MAC", err)
	}
	return hop, nil
}
