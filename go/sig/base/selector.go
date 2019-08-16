// Copyright 2018 ETH Zurich
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

package base

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/sig/egress"
)

// SessionSelector implements egress.SessionSelector, returning the contained
// session on ChooseSess.
type SessionSelector struct {
	Session egress.Session
}

func (ss *SessionSelector) ChooseSess(b common.RawBytes) egress.Session {
	return ss.Session
}
