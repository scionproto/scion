// Copyright 2017 ETH Zurich
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

package opt

import (
	//"fmt"
	"github.com/netsec-ethz/scion/go/lib/common"
)

// https://github.com/Oncilla/scion-detached/blob/opt/lib/opt/ext/opt.py definitions

// defines the lengths used by the Origin validation & PathTrace (OPT) extension

const (
	// Basic definitions
	MetaLength      = 1
	TimestampLength = 4
	DatahashLength  = 16
	SessionIDLength = 16
	PVFLength       = 16
)

func NewExtn() (*Extn, *common.Error) {
	o := &Extn{}
	o.Meta = make(common.RawBytes, MetaLength)
	o.Timestamp = make(common.RawBytes, TimestampLength)
	o.DataHash = make(common.RawBytes, DatahashLength)
	o.SessionId = make(common.RawBytes, SessionIDLength)
	o.PVF = make(common.RawBytes, PVFLength)
	return o, nil
}

type RawBlock int
