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

//    DRKeyMac:
//
//    0B       1        2        3        4        5        6        7
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x04  |              padding              |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                              DRKey MAC                                |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                              DRKey MAC (continued)                    |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//
//    HashTree:
//
//    0B       1        2        3        4        5        6        7
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x05  | Height |            Order         |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                               Signature (8 lines)                     |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                               Hashes (height * 2)                     |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//

package scmp_auth_extn

import (
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sec_extn"
)

type SCMPAuthExtn struct {
	sec_extn.SecurityExtn
}

const (
	HASH_LENGTH      = 16
	HEIGHT_LENGTH    = 1
	ORDER_LENGTH     = 3
	SIGNATURE_LENGTH = 64
	MAC_LENGTH       = 16

	HEIGHT_OFFSET = 0
	ORDER_OFFSET  = HEIGHT_OFFSET

	DRKEY_META_LENGTH  = 4 // padding
	DRKEY_AUTH_LENGTH  = MAC_LENGTH
	DRKEY_TOTAL_LENGTH = sec_extn.SECMODE_LENGTH + DRKEY_META_LENGTH + DRKEY_AUTH_LENGTH

	HASH_TREE_META_LENGTH = HEIGHT_LENGTH + ORDER_LENGTH
)

func NewSCMPDRKeyAuthExtn(SecMode uint8) (*SCMPAuthExtn, *common.Error) {
	if SecMode != sec_extn.SCMP_AUTH_DRKEY {
		return nil, common.NewError("Invalid secmode code.", "SecMode", SecMode)
	}
	s := &SCMPAuthExtn{SecurityExtn: sec_extn.SecurityExtn{SecMode: SecMode}}
	s.Metadata = make(common.RawBytes, DRKEY_META_LENGTH)
	s.Authenticator = make(common.RawBytes, DRKEY_AUTH_LENGTH)
	return s, nil
}

func NewSCMPHashedTreeExtn(SecMode uint8, treeHeight uint8) (*SCMPAuthExtn, *common.Error) {
	s := &SCMPAuthExtn{SecurityExtn: sec_extn.SecurityExtn{SecMode: SecMode}}

	var metaLen, authLen int

	switch SecMode {
	case sec_extn.SCMP_AUTH_HASH_TREE:
		metaLen = HASH_TREE_META_LENGTH
		authLen = SIGNATURE_LENGTH + HASH_LENGTH*int(treeHeight)
	default:
		return nil, common.NewError("Invalid secmode code.", "SecMode", SecMode)
	}

	s.Metadata = make(common.RawBytes, metaLen)
	s.Authenticator = make(common.RawBytes, authLen)

	return s, nil
}

func (s SCMPAuthExtn) UpdateMAC(mac common.RawBytes) *common.Error {
	if s.SecMode == sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No MAC for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator, mac)
	return nil
}

func (s SCMPAuthExtn) MAC() common.RawBytes {
	if s.SecMode == sec_extn.SCMP_AUTH_DRKEY {
		return s.Authenticator
	}
	return s.Authenticator[0:0]
}

func (s SCMPAuthExtn) UpdateHeight(height uint8) *common.Error {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No order for this header", "SecMode", s.SecMode)
	}
	s.Metadata[0] = height
	return nil

}

func (s SCMPAuthExtn) Height() uint8 {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return 0
	}
	return s.Metadata[0]
}

func (s SCMPAuthExtn) UpdateOrder(order common.RawBytes) *common.Error {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No order for this header", "SecMode", s.SecMode)
	}
	copy(s.Metadata[HEIGHT_LENGTH:], order)
	return nil

}

func (s SCMPAuthExtn) Order() common.RawBytes {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return s.Metadata[0:0]
	}
	return s.Metadata[HEIGHT_LENGTH:]
}

func (s SCMPAuthExtn) UpdateSignature(signature common.RawBytes) *common.Error {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No signature for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator[:SIGNATURE_LENGTH], signature)
	return nil

}

func (s SCMPAuthExtn) Signature() common.RawBytes {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return s.Authenticator[0:0]
	}
	return s.Authenticator[:SIGNATURE_LENGTH]
}

func (s SCMPAuthExtn) UpdateHashes(hashes common.RawBytes) *common.Error {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No hashes for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator[SIGNATURE_LENGTH:], hashes)
	return nil

}

func (s SCMPAuthExtn) Hashes() common.RawBytes {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return s.Authenticator[0:0]
	}
	return s.Authenticator[SIGNATURE_LENGTH:]
}
