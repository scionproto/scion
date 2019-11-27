// Copyright 2019 ETH Zurich
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

package layers

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
)

var _ common.Extension = (*ExtnPathTrans)(nil)

const hostTypeLen = 1

var (
	errExtnPathTransBadLength = serrors.New("bad length for path transport extension")
)

type ExtnPathTrans struct {
	SrcIA   addr.IA
	SrcHost addr.HostAddr
	Path    *spath.Path
}

func NewExtnPathTransFromLayer(extension *Extension) (*ExtnPathTrans, error) {
	var extn ExtnPathTrans
	if err := extn.DecodeFromLayer(extension); err != nil {
		return nil, err
	}
	return &extn, nil
}

func (o *ExtnPathTrans) DecodeFromLayer(extension *Extension) error {
	if len(extension.Data) == 0 {
		return errExtnPathTransBadLength
	}

	b := common.RawBytes(extension.Data)
	offset := 0

	srcT := addr.HostAddrType(b[offset])
	offset += 1
	addrLen, err := o.parseAddr(b[offset:], srcT)
	if err != nil {
		return err
	}
	offset = paddedExtnPldLen(offset + addrLen)
	err = o.parsePath(b[offset:])
	if err != nil {
		return err
	}
	return nil
}

func (o *ExtnPathTrans) Write(b common.RawBytes) error {
	offset := 0

	hostType := addr.HostTypeNone
	if o.SrcHost != nil {
		hostType = o.SrcHost.Type()
	}
	b[offset] = uint8(hostType)
	offset += 1

	o.SrcIA.Write(b[offset:])
	offset += addr.IABytes

	if o.SrcHost != nil {
		srcHost := o.SrcHost.Pack()
		copy(b[offset:], srcHost)
		offset += len(srcHost)
	} else {
		offset += addr.HostLenNone
	}

	offset = fillExtnPldPadding(b, offset)

	if o.Path != nil {
		copy(b[offset:], o.Path.Raw)
	}
	return nil
}

func (o *ExtnPathTrans) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, o.Len())
	if err := o.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (o *ExtnPathTrans) Copy() common.Extension {
	var h addr.HostAddr
	if o.SrcHost != nil {
		h = o.SrcHost.Copy()
	}
	var p *spath.Path
	if o.Path != nil {
		p = o.Path.Copy()
	}
	return &ExtnPathTrans{
		SrcIA:   o.SrcIA,
		SrcHost: h,
		Path:    p,
	}
}

func (o *ExtnPathTrans) Reverse() (bool, error) {
	return false, nil
}

func (o *ExtnPathTrans) Len() int {
	var hostLen uint8
	if o.SrcHost != nil {
		hostLen, _ = addr.HostLen(o.SrcHost.Type())
	}
	paddedAddrLen := paddedExtnPldLen(hostTypeLen + addr.IABytes + int(hostLen))
	var pathLen int
	if o.Path != nil {
		pathLen = len(o.Path.Raw)
	}
	return paddedAddrLen + pathLen
}

func (o *ExtnPathTrans) Class() common.L4ProtocolType {
	return common.End2EndClass
}

func (o *ExtnPathTrans) Type() common.ExtnType {
	return common.ExtnPathTransType
}

func (o *ExtnPathTrans) String() string {
	return "E2EPathTrans"
}

func paddedExtnPldLen(length int) int {
	return util.PaddedLen(common.ExtnSubHdrLen+length, common.LineLen) - common.ExtnSubHdrLen
}

func fillExtnPldPadding(b common.RawBytes, length int) int {
	padded := paddedExtnPldLen(length)
	for i := range b[length:padded] {
		b[length+i] = 0
	}
	return padded
}

func (o *ExtnPathTrans) parseAddr(b common.RawBytes, srcT addr.HostAddrType) (int, error) {
	srcLen, err := addr.HostLen(srcT)
	if err != nil {
		return 0, err
	}
	addrLen := addr.IABytes + int(srcLen)
	if len(b) < addrLen {
		return 0, errExtnPathTransBadLength
	}
	ia := addr.IAFromRaw(b)
	host, err := addr.HostFromRaw(b[addr.IABytes:], srcT)
	if err != nil {
		return 0, err
	}
	o.SrcIA = ia
	o.SrcHost = host
	return addrLen, nil
}

func (o *ExtnPathTrans) parsePath(b common.RawBytes) error {
	if len(b) > 0 {
		o.Path = spath.New(b)
		if err := o.Path.InitOffsets(); err != nil {
			return err
		}
	}
	return nil
}
