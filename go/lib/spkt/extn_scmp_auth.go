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

//    DRKeyMac:
//
//    0B       1        2        3        4        5        6        7
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x04  |             Timestamp             |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                              DRKey MAC                                |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                              DRKey MAC (continued)                    |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//
//    Hashed DRKeyMac:
//
//    0B       1        2        3        4        5        6        7
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x05  |             Timestamp             |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                              SHA256(pkt)                              |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                              SHA256(pkt) (cont)                       |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                              DRKey MAC                                |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                              DRKey MAC (cont)                         |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//
//    HashTree:
//
//    0B       1        2        3        4        5        6        7
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x06  |             Timestamp             |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    | Height |                        Order                                 |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                               Signature (8 lines)                     |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                               Hashes (height * 2)                     |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//

package spkt

import (
	"github.com/netsec-ethz/scion/go/lib/common"
	"time"
)

type SCMPAuthExtn struct {
	SecurityExtn
}

const (
	// Basic definitions
	HASH_LENGTH      = 16
	HEIGHT_LENGTH    = 1
	ORDER_LENGTH     = 7
	SIGNATURE_LENGTH = 64
	MAC_LENGTH       = 16

	// Metadata length (Shall be 4 + i*8, were i in [0,1,...])
	SCMP_AUTH_DRKEY_META_LENGTH        = TIMESTAMP_LENGTH
	SCMP_AUTH_HASHED_DRKEY_META_LENGTH = TIMESTAMP_LENGTH + HASH_LENGTH
	SCMP_AUTH_HASH_TREE_META_LENGTH    = TIMESTAMP_LENGTH + HEIGHT_LENGTH + ORDER_LENGTH

	// Authenticator length
	SCMP_AUTH_DRKEY_AUTH_LENGTH        = MAC_LENGTH
	SCMP_AUTH_HASHED_DRKEY_AUTH_LENGTH = MAC_LENGTH

	// Metadata length (Shall be 4 + i*8, were i in [0,1,...])
	SCMP_AUTH_DRKEY_TOTAL_LENGTH        = SECMODE_LENGTH + SCMP_AUTH_DRKEY_META_LENGTH + SCMP_AUTH_DRKEY_AUTH_LENGTH
	SCMP_AUTH_HASHED_DRKEY_TOTAL_LENGTH = SECMODE_LENGTH + SCMP_AUTH_HASHED_DRKEY_META_LENGTH + SCMP_AUTH_HASHED_DRKEY_AUTH_LENGTH
)

func NewSCMPDRKeyAuthExtn(SecMode uint8) *SCMPAuthExtn {
	s := &SCMPAuthExtn{SecurityExtn: SecurityExtn{SecMode: SecMode}}

	var metaLen, authLen int

	switch SecMode {
	case SCMP_AUTH_DRKEY:
		metaLen = SCMP_AUTH_DRKEY_META_LENGTH
		authLen = SCMP_AUTH_DRKEY_AUTH_LENGTH
	case SCMP_AUTH_HASHED_DRKEY:
		metaLen = SCMP_AUTH_HASHED_DRKEY_META_LENGTH
		authLen = SCMP_AUTH_HASHED_DRKEY_AUTH_LENGTH
	case SCMP_AUTH_HASH_TREE:
		panic("Wrong Initializer. Use NewSCMPHashedTreeExtn insted!")
		//TODO(roosd) Handle more gracefully
	default:
		panic("Invalid SecMode!")
	}

	s.Metadata = make(common.RawBytes, metaLen)
	s.Authenticator = make(common.RawBytes, authLen)

	return s
}

func NewSCMPHashedTreeExtn(SecMode uint8, treeHeight uint8) *SCMPAuthExtn {
	s := &SCMPAuthExtn{SecurityExtn: SecurityExtn{SecMode: SecMode}}

	var metaLen, authLen int

	switch SecMode {
	case SCMP_AUTH_HASH_TREE:
		metaLen = SCMP_AUTH_HASH_TREE_META_LENGTH
		authLen = SIGNATURE_LENGTH + HASH_LENGTH*int(treeHeight)
	default:
		panic("Invalid SecMode!")
		// TODO(roosd) Handle case, but should not be possible!
	}

	s.Metadata = make(common.RawBytes, metaLen)
	s.Authenticator = make(common.RawBytes, authLen)

	return s
}

func (s SCMPAuthExtn) SetTimeStamp() {
	common.Order.PutUint32(s.Metadata[:TIMESTAMP_LENGTH], uint32(time.Now().Unix()))
}

func (s SCMPAuthExtn) UpdateTimeStamp(timestamp common.RawBytes) {
	copy(s.Metadata[:TIMESTAMP_LENGTH], timestamp)
}

func (s SCMPAuthExtn) TimeStamp() common.RawBytes {
	return s.Metadata[:TIMESTAMP_LENGTH]
}

func (s SCMPAuthExtn) UpdatePktHash(hash common.RawBytes) *common.Error {
	if s.SecMode != SCMP_AUTH_HASHED_DRKEY {
		return common.NewError("No packet hash for this header", "SecMode", s.SecMode)
	}
	copy(s.Metadata[TIMESTAMP_LENGTH:], hash)
	return nil
}

func (s SCMPAuthExtn) PktHash() common.RawBytes {
	if s.SecMode == SCMP_AUTH_HASHED_DRKEY {
		return s.Metadata[TIMESTAMP_LENGTH:]
	}
	return s.Metadata[0:0]
}

func (s SCMPAuthExtn) UpdateMAC(mac common.RawBytes) *common.Error {
	if s.SecMode == SCMP_AUTH_HASH_TREE {
		return common.NewError("No MAC for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator, mac)
	return nil
}

func (s SCMPAuthExtn) MAC() common.RawBytes {
	if s.SecMode == SCMP_AUTH_HASHED_DRKEY || s.SecMode == SCMP_AUTH_DRKEY {
		return s.Authenticator
	}
	return s.Authenticator[0:0]
}

func (s SCMPAuthExtn) UpdateHeight(height uint8) *common.Error {
	if s.SecMode != SCMP_AUTH_HASH_TREE {
		return common.NewError("No order for this header", "SecMode", s.SecMode)
	}
	s.Metadata[TIMESTAMP_LENGTH] = height
	return nil

}

func (s SCMPAuthExtn) Height() uint8 {
	if s.SecMode != SCMP_AUTH_HASH_TREE {
		return 0
	}
	return s.Metadata[TIMESTAMP_LENGTH]
}

func (s SCMPAuthExtn) UpdateOrder(order common.RawBytes) *common.Error {
	if s.SecMode != SCMP_AUTH_HASH_TREE {
		return common.NewError("No order for this header", "SecMode", s.SecMode)
	}
	copy(s.Metadata[TIMESTAMP_LENGTH+HEIGHT_LENGTH:], order)
	return nil

}

func (s SCMPAuthExtn) Order() common.RawBytes {
	if s.SecMode != SCMP_AUTH_HASH_TREE {
		return s.Metadata[0:0]
	}
	return s.Metadata[TIMESTAMP_LENGTH+HEIGHT_LENGTH:]
}

func (s SCMPAuthExtn) UpdateSignature(signature common.RawBytes) *common.Error {
	if s.SecMode != SCMP_AUTH_HASH_TREE {
		return common.NewError("No signature for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator[:SIGNATURE_LENGTH], signature)
	return nil

}

func (s SCMPAuthExtn) Signature() common.RawBytes {
	if s.SecMode != SCMP_AUTH_HASH_TREE {
		return s.Authenticator[0:0]
	}
	return s.Authenticator[:SIGNATURE_LENGTH]
}

func (s SCMPAuthExtn) UpdateHashes(hashes common.RawBytes) *common.Error {
	if s.SecMode != SCMP_AUTH_HASH_TREE {
		return common.NewError("No hashes for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator[SIGNATURE_LENGTH:], hashes)
	return nil

}

func (s SCMPAuthExtn) Hashes() common.RawBytes {
	if s.SecMode != SCMP_AUTH_HASH_TREE {
		return s.Authenticator[0:0]
	}
	return s.Authenticator[SIGNATURE_LENGTH:]
}
