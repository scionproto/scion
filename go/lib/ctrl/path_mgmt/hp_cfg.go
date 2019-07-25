// Copyright 2019 ETH Zurich, Anapaya Systems
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

package path_mgmt

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*HPGroupId)(nil)

type HPGroupId struct {
	OwnerAS addr.AS
	GroupId uint16
}

func (id *HPGroupId) ProtoId() proto.ProtoIdType {
	return proto.HPGroupId_TypeID
}

func (id *HPGroupId) String() string {
	return fmt.Sprintf("{OwnerAS: %s, GroupId %d}", id.OwnerAS, id.GroupId)
}

var _ proto.Cerealizable = (*HPCfg)(nil)

type HPCfg struct {
	GroupId    *HPGroupId
	Version    uint32
	OwnerISD   uint16
	Writers    []addr.IAInt
	Readers    []addr.IAInt
	Registries []addr.IAInt
}

func (hc *HPCfg) ProtoId() proto.ProtoIdType {
	return proto.HPCfg_TypeID
}

func (hc *HPCfg) String() string {
	return fmt.Sprintf(
		"{ID: %s, Version: %d, OwnerISD: %d, Writers: %v, Readers: %v, Registries: %v}",
		hc.GroupId, hc.Version, hc.OwnerISD, hc.Writers, hc.Readers, hc.Registries)
}

var _ proto.Cerealizable = (*HPCfgReq)(nil)

type HPCfgReq struct {
	ChangedSince uint32
}

func (hr *HPCfgReq) ProtoId() proto.ProtoIdType {
	return proto.HPCfgReq_TypeID
}

func (hr *HPCfgReq) String() string {
	return fmt.Sprintf("ChangedSince %d", hr.ChangedSince)
}

var _ proto.Cerealizable = (*HPCfgReply)(nil)

type HPCfgReply struct {
	Cfgs []*HPCfg
}

func (hr *HPCfgReply) ProtoId() proto.ProtoIdType {
	return proto.HPCfgReply_TypeID
}

func (hr *HPCfgReply) String() string {
	desc := []string{"["}
	for _, c := range hr.Cfgs {
		desc = append(desc, "  "+c.String())
	}
	return strings.Join(desc, "\n") + "\n]"
}
