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

package cs

import (
	"context"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/revcache"
)

// RevocationHandler handles raw revocations from the snet stack and inserts
// them into the
type RevocationHandler struct {
	RevCache revcache.RevCache
}

func (h RevocationHandler) RevokeRaw(ctx context.Context, rawSRevInfo []byte) {
	logger := log.FromCtx(ctx)
	sRev, err := path_mgmt.NewSignedRevInfoFromRaw(rawSRevInfo)
	if err != nil {
		logger.Debug("Unparsable revocation received", "err", err)
	}
	_, err = h.RevCache.Insert(ctx, sRev)
	if err != nil {
		logger.Debug("Failed to insert revocation from snet", "err", err)
	}
}
