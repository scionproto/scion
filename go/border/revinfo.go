// Copyright 2016 ETH Zurich
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

// This file handles Revocation Info (RevInfo) packets.

package main

import (
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/log"
)

// RawSRevCallback is called to enqueue RevInfos for handling by the
// RevInfoFwd goroutine.
func (r *Router) RawSRevCallback(args rpkt.RawSRevCallbackArgs) {
	// TODO #1867 filter revocations to avoid sending the same one to Control-plane multiple times.
	select {
	case r.sRevInfoQ <- args:
	default:
		log.Debug("Dropping rev token")
	}
}
