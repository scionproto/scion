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

// This file contains the declarations of the system of hooks, used for
// callbacks.

package rpkt

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

type HookIA func() (HookResult, *addr.ISD_AS, *common.Error)
type HookHost func() (HookResult, addr.HostAddr, *common.Error)
type HookInfoF func() (HookResult, *spath.InfoField, *common.Error)
type HookHopF func() (HookResult, *spath.HopField, *common.Error)
type HookBool func() (HookResult, bool, *common.Error)
type HookIntf func(up bool, dirFrom, dirTo Dir) (HookResult, spath.IntfID, *common.Error)
type HookValidate func() (HookResult, *common.Error)
type HookL4 func() (HookResult, l4.L4Header, *common.Error)
type HookPayload func() (HookResult, common.Payload, *common.Error)
type HookProcess func() (HookResult, *common.Error)
type HookRoute func() (HookResult, *common.Error)

// Hooks is a group of hook slices. Each hook slice is responsible for fetching
// the information named by the slice from a packet. Extensions and other parts
// of the router register to handle certain functions by adding a callback to
// the relevant slice.
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
	// HookError means the current hook has failed.
	HookError HookResult = iota
	// HookContinue means the caller should continue to call other hooks.
	HookContinue
	// HookFinish means the current hook has provided the definitive answer,
	// and no further hooks should be called.
	HookFinish
)
