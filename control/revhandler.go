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
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/private/revcache"
)

// RevocationHandler handles raw revocations from the snet stack and inserts
// them into the
type RevocationHandler struct {
	RevCache revcache.RevCache
}

func (h RevocationHandler) Revoke(ia addr.IA, ingress, egress uint64) error {
	revInfo := &path_mgmt.RevInfo{
		IfID:         common.IFIDType(egress),
		RawIsdas:     ia,
		RawTimestamp: util.TimeToSecs(time.Now()),
		RawTTL:       10,
	}
	_, _ = h.RevCache.Insert(context.TODO(), revInfo)
	return nil
}
