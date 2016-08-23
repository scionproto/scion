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

package packet

import (
	"github.com/netsec-ethz/scion/go/border/path"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type HookIA func() (HookResult, *addr.ISD_AS, *util.Error)
type HookHost func() (HookResult, addr.HostAddr, *util.Error)
type HookInfoF func() (HookResult, *path.InfoField, *util.Error)
type HookHopF func() (HookResult, *path.HopField, *util.Error)
type HookBool func() (HookResult, bool, *util.Error)
type HookIntf func(up bool, dirFrom, dirTo Dir) (HookResult, path.IntfID, *util.Error)
type HookValidate func() (HookResult, *util.Error)
type HookL4 func() (HookResult, interface{}, *util.Error)
type HookPayload func() (HookResult, interface{}, *util.Error)
type HookProcess func() (HookResult, *util.Error)
type HookRoute func() (HookResult, *util.Error)

type Hooks struct {
	SrcIA    []HookIA
	SrcHost  []HookHost
	DstIA    []HookIA
	DstHost  []HookHost
	Infof    []HookInfoF
	HopF     []HookHopF
	UpFlag   []HookBool
	IFCurr   []HookIntf
	IFNext   []HookIntf
	Validate []HookValidate
	L4       []HookL4
	Payload  []HookPayload
	Process  []HookProcess
	Route    []HookRoute
}

type HookResult int

const (
	HookError HookResult = iota
	HookContinue
	HookFinish
)
