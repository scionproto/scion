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

package main

import (
	"time"

	"github.com/scionproto/scion/go/border/braccept/tpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
)

var (
	if_121 = common.IFIDType(121)
	if_122 = common.IFIDType(122)
	if_131 = common.IFIDType(131)
	if_132 = common.IFIDType(132)
	if_141 = common.IFIDType(141)
	if_142 = common.IFIDType(142)
	if_151 = common.IFIDType(151)
	if_152 = common.IFIDType(152)
	if_161 = common.IFIDType(161)
	if_162 = common.IFIDType(162)
	if_171 = common.IFIDType(171)
	if_172 = common.IFIDType(172)
	if_211 = common.IFIDType(211)
	if_212 = common.IFIDType(212)
	if_261 = common.IFIDType(261)
	if_311 = common.IFIDType(311)
	if_312 = common.IFIDType(312)
	if_381 = common.IFIDType(381)
	if_411 = common.IFIDType(411)
	if_412 = common.IFIDType(412)
	if_511 = common.IFIDType(511)
	if_512 = common.IFIDType(512)
	if_611 = common.IFIDType(611)
	if_612 = common.IFIDType(612)
	if_621 = common.IFIDType(621)
	if_711 = common.IFIDType(711)
	if_712 = common.IFIDType(712)
	if_831 = common.IFIDType(831)
)

var tsNow = uint32(time.Now().Unix())

var ifStateReq = &tpkt.PathMgmtPld{
	Signer:      ctrl.NullSigner,
	SigVerifier: ctrl.NullSigVerifier,
	Instance:    &path_mgmt.IFStateReq{},
}
