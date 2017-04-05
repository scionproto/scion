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

// This file contains the router's representation of the end-2-end SCMPAuth
// extension.

package rpkt

import (
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spkt"
)

func hashTreeTotalLength(height uint8) int {
	return spkt.SECMODE_LENGTH + spkt.SCMP_AUTH_HASH_TREE_META_LENGTH + spkt.SIGNATURE_LENGTH + int(height)*spkt.HASH_LENGTH
}

func hashTreeHeight(raw common.RawBytes) uint8 {
	return raw[spkt.SECMODE_LENGTH+spkt.TIMESTAMP_LENGTH]
}

func (s *rSecurityExt) UpdateTimeStamp(timestamp common.RawBytes) {
	copy(s.Metadata()[:spkt.TIMESTAMP_LENGTH], timestamp)
}

func (s *rSecurityExt) TimeStamp() common.RawBytes {
	return s.Metadata()[:spkt.TIMESTAMP_LENGTH]
}

func (s *rSecurityExt) UpdatePktHash(hash common.RawBytes) *common.Error {
	if s.SecMode != spkt.SCMP_AUTH_HASHED_DRKEY {
		return common.NewError("No packet hash for this header", "SecMode", s.SecMode)
	}
	copy(s.Metadata()[spkt.TIMESTAMP_LENGTH:], hash)
	return nil
}

func (s *rSecurityExt) PktHash() common.RawBytes {
	if s.SecMode == spkt.SCMP_AUTH_HASHED_DRKEY {
		return s.Metadata()[spkt.TIMESTAMP_LENGTH:]
	}
	return s.Metadata()[0:0]
}

func (s *rSecurityExt) ResetMac() *common.Error {
	if s.SecMode == spkt.SCMP_AUTH_HASH_TREE {
		return common.NewError("No MAC for this header", "SecMode", s.SecMode)
	}
	for i := range s.Authenticator() {
		s.Authenticator()[i] = 0
	}
	return nil
}

func (s *rSecurityExt) UpdateMAC(mac common.RawBytes) *common.Error {
	if s.SecMode == spkt.SCMP_AUTH_HASH_TREE {
		return common.NewError("No MAC for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator(), mac)
	return nil
}

func (s *rSecurityExt) MAC() common.RawBytes {
	if s.SecMode == spkt.SCMP_AUTH_HASHED_DRKEY || s.SecMode == spkt.SCMP_AUTH_DRKEY {
		return s.Authenticator()
	}
	return s.Authenticator()[0:0]
}

func (s *rSecurityExt) UpdateHeight(height uint8) *common.Error {
	if s.SecMode != spkt.SCMP_AUTH_HASH_TREE {
		return common.NewError("No order for this header", "SecMode", s.SecMode)
	}
	s.Metadata()[spkt.TIMESTAMP_LENGTH] = height
	return nil

}

func (s *rSecurityExt) Height() uint8 {
	if s.SecMode != spkt.SCMP_AUTH_HASH_TREE {
		return 0
	}
	return s.Metadata()[spkt.TIMESTAMP_LENGTH]
}

func (s *rSecurityExt) UpdateOrder(order common.RawBytes) *common.Error {
	if s.SecMode != spkt.SCMP_AUTH_HASH_TREE {
		return common.NewError("No order for this header", "SecMode", s.SecMode)
	}
	copy(s.Metadata()[spkt.TIMESTAMP_LENGTH+spkt.HEIGHT_LENGTH:], order)
	return nil

}

func (s *rSecurityExt) Order() common.RawBytes {
	if s.SecMode != spkt.SCMP_AUTH_HASH_TREE {
		return s.Metadata()[0:0]
	}
	return s.Metadata()[spkt.TIMESTAMP_LENGTH+spkt.HEIGHT_LENGTH:]
}

func (s *rSecurityExt) UpdateSignature(signature common.RawBytes) *common.Error {
	if s.SecMode != spkt.SCMP_AUTH_HASH_TREE {
		return common.NewError("No signature for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator()[:spkt.SIGNATURE_LENGTH], signature)
	return nil

}

func (s *rSecurityExt) Signature() common.RawBytes {
	if s.SecMode != spkt.SCMP_AUTH_HASH_TREE {
		return s.Authenticator()[0:0]
	}
	return s.Authenticator()[:spkt.SIGNATURE_LENGTH]
}

func (s *rSecurityExt) UpdateHashes(hashes common.RawBytes) *common.Error {
	if s.SecMode != spkt.SCMP_AUTH_HASH_TREE {
		return common.NewError("No hashes for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator()[spkt.SIGNATURE_LENGTH:], hashes)
	return nil

}

func (s *rSecurityExt) Hashes() common.RawBytes {
	if s.SecMode != spkt.SCMP_AUTH_HASH_TREE {
		return s.Authenticator()[0:0]
	}
	return s.Authenticator()[spkt.SIGNATURE_LENGTH:]
}

func (s *rSecurityExt) AlreadySet() bool {
	l, h := limitsMetadata(s.SecMode)
	_ = l
	auth := s.raw[h:]
	for i := 0; i < len(auth); i++ {
		if auth[i] != 0 {
			return true
		}
	}
	return false
}
