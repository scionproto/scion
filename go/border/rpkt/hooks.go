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

type hookIA func() (HookResult, *addr.ISD_AS, *common.Error)
type hookHost func() (HookResult, addr.HostAddr, *common.Error)
type hookInfoF func() (HookResult, *spath.InfoField, *common.Error)
type hookHopF func() (HookResult, *spath.HopField, *common.Error)
type hookBool func() (HookResult, bool, *common.Error)
type hookIntf func(up bool, dirFrom, dirTo Dir) (HookResult, spath.IntfID, *common.Error)
type hookValidate func() (HookResult, *common.Error)
type hookL4 func() (HookResult, l4.L4Header, *common.Error)
type hookPayload func() (HookResult, common.Payload, *common.Error)
type hookProcess func() (HookResult, *common.Error)
type hookRoute func() (HookResult, *common.Error)

// Hooks is a group of hook slices. Each hook slice is responsible for fetching
// the information named by the slice from a packet. Extensions and other parts
// of the router register to handle certain functions by adding a callback to
// the relevant slice.
type hooks struct {
	SrcIA    []hookIA
	SrcHost  []hookHost
	DstIA    []hookIA
	DstHost  []hookHost
	Infof    []hookInfoF
	HopF     []hookHopF
	UpFlag   []hookBool
	IFCurr   []hookIntf
	IFNext   []hookIntf
	Validate []hookValidate
	L4       []hookL4
	Payload  []hookPayload
	Process  []hookProcess
	Route    []hookRoute
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
