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

package seg

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*PathSegmentSigned)(nil)

type PathSegmentSigned struct {
	RawInfo common.RawBytes `capnp:"infoF"`
}

func newPathSegmentSigned(infoF *spath.InfoField) *PathSegmentSigned {
	pss := &PathSegmentSigned{RawInfo: make(common.RawBytes, spath.InfoFieldLength)}
	infoF.Write(pss.RawInfo)
	return pss
}

func NewPathSegmentSignedFromRaw(b common.RawBytes) (*PathSegmentSigned, error) {
	pss := &PathSegmentSigned{}
	return pss, proto.ParseFromRaw(pss, pss.ProtoId(), b)
}

func (pss *PathSegmentSigned) InfoF() (*spath.InfoField, error) {
	return spath.InfoFFromRaw(pss.RawInfo)
}

func (pss *PathSegmentSigned) ProtoId() proto.ProtoIdType {
	return proto.PathSegmentSigned_TypeID
}

func (pss *PathSegmentSigned) String() string {
	info, err := pss.InfoF()
	if err != nil {
		return fmt.Sprintf("InfoF: %s (parse err: %s)", pss.RawInfo, err)
	}
	return fmt.Sprintf("InfoF: %s", info)
}
