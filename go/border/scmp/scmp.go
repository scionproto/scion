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
	"encoding/binary"

	log "github.com/inconshreveable/log15"
	"gopkg.in/restruct.v1"

	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	SCMPHdrLen = 16
)

const (
	ErrorSCMPHdrUnpack = "Failed to unpack SCMP header"
)

// TODO(kormat): lots and lots of work needed for SCMP support.

//var _ Extension = (*SCMP)(nil)

type SCMP struct {
	data util.RawBytes
	Hdr  *SCMPHeader
	Info *SCMPInfo
	log.Logger
}

func SCMPFromRaw(b []byte, logger log.Logger) (*SCMP, *util.Error) {
	s := &SCMP{}
	s.data = b
	s.Logger = logger
	s.Debug("SCMP header found")
	return s, nil
}

type SCMPHeader struct {
	Class     uint16
	Type      uint16
	Len       uint16
	Checksum  [2]byte
	Timestamp [8]byte
}

func SCMPHdrFromRaw(b []byte) (*SCMPHeader, *util.Error) {
	s := &SCMPHeader{}
	if err := restruct.Unpack(b, binary.BigEndian, s); err != nil {
		return nil, util.NewError(ErrorSCMPHdrUnpack, "err", err)
	}
	return s, nil
}

type SCMPInfo struct {
}
