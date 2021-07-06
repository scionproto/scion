// Copyright 2021 ETH Zurich, Anapaya Systems
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

// This file contains an SQLite backend for the PathDB.

package utils

import (
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
)

func ExtractLastHopVersion(ps *seg.PathSegment) (int64, error) {
	ases := ps.ASEntries
	if len(ases) == 0 {
		return 0, serrors.New("segment without AS Entries")
	}
	sign := ases[len(ases)-1].Signed
	hdr, err := signed.ExtractUnverifiedHeader(sign)
	if err != nil {
		return 0, err
	}
	return hdr.Timestamp.UnixNano(), nil
}
