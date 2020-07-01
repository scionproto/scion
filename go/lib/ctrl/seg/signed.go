// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

package seg

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*PathSegmentSignedData)(nil)

type PathSegmentSignedData struct {
	RawTimestamp uint32 `capnp:"timestamp"`
	SegID        uint16 `capnp:"segID"`

	// TODO(roosd): Remove when completely switching to v2.
	RawInfo common.RawBytes `capnp:"infoF"`
	ISD     addr.ISD        `capnp:"-"`
}

func NewPathSegmentSignedDataFromRaw(b []byte) (*PathSegmentSignedData, error) {
	pss := &PathSegmentSignedData{}
	if err := proto.ParseFromRaw(pss, b); err != nil {
		return nil, err
	}
	if len(pss.RawInfo) == 0 {
		return pss, nil
	}
	info, err := spath.InfoFFromRaw(pss.RawInfo)
	if err != nil {
		return nil, err
	}
	pss.RawTimestamp = info.TsInt
	pss.ISD = addr.ISD(info.ISD)
	return pss, nil
}

func (pss *PathSegmentSignedData) Validate() error {
	if len(pss.RawInfo) > 0 {
		_, err := spath.InfoFFromRaw(pss.RawInfo)
		return err
	}
	return nil
}

func (pss *PathSegmentSignedData) ProtoId() proto.ProtoIdType {
	return proto.PathSegmentSignedData_TypeID
}

func (pss *PathSegmentSignedData) String() string {
	info, err := spath.InfoFFromRaw(pss.RawInfo)
	if err != nil {
		return fmt.Sprintf("InfoF: %s (parse err: %s)", pss.RawInfo, err)
	}
	return fmt.Sprintf("InfoF: %s", info)
}
