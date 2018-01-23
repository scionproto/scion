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

// This file contains the Go representation of IFState requests.

package path_mgmt

import (
	"fmt"
	"strings"

	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*IFStateInfos)(nil)

type IFStateInfos struct {
	Infos []*IFStateInfo
}

func (i *IFStateInfos) ProtoId() proto.ProtoIdType {
	return proto.IFStateInfos_TypeID
}

func (i *IFStateInfos) String() string {
	desc := []string{"Infos"}
	for _, info := range i.Infos {
		desc = append(desc, info.String())
	}
	return strings.Join(desc, "\n")
}

type IFStateInfo struct {
	IfID    uint64
	Active  bool
	RevInfo *RevInfo
}

func (i *IFStateInfo) String() string {
	desc := fmt.Sprintf("IfID: %v, Active: %v", i.IfID, i.Active)
	if i.RevInfo != nil {
		desc += fmt.Sprintf(", RevInfo: %v", i.RevInfo)
	}
	return desc
}
