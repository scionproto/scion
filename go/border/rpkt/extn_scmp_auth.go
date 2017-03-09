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

// This file contains the router's representation of the end-2-end SCMPAuth
// extension.

package rpkt

import (
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sec_extn"
	"github.com/netsec-ethz/scion/go/lib/sec_extn/scmp_auth_extn"
)

func hashTreeTotalLength(height uint8) int {
	return sec_extn.SECMODE_LENGTH + scmp_auth_extn.HASH_TREE_META_LENGTH + scmp_auth_extn.SIGNATURE_LENGTH + int(height)*scmp_auth_extn.HASH_LENGTH
}

func hashTreeHeight(raw common.RawBytes) uint8 {
	return raw[sec_extn.SECMODE_LENGTH]
}

func (s *rSecurityExt) ResetMac() *common.Error {
	if s.SecMode == sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No MAC for this header", "SecMode", s.SecMode)
	}
	for i := range s.Authenticator() {
		s.Authenticator()[i] = 0
	}
	return nil
}

func (s *rSecurityExt) UpdateMAC(mac common.RawBytes) *common.Error {
	if s.SecMode == sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No MAC for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator(), mac)
	return nil
}

func (s *rSecurityExt) MAC() common.RawBytes {
	if s.SecMode == sec_extn.SCMP_AUTH_DRKEY {
		return s.Authenticator()
	}
	return s.Authenticator()[0:0]
}

func (s *rSecurityExt) UpdateHeight(height uint8) *common.Error {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No order for this header", "SecMode", s.SecMode)
	}
	s.Metadata()[scmp_auth_extn.HEIGHT_OFFSET] = height
	return nil

}

func (s *rSecurityExt) Height() uint8 {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return 0
	}
	return s.Metadata()[scmp_auth_extn.HEIGHT_OFFSET]
}

func (s *rSecurityExt) UpdateOrder(order common.RawBytes) *common.Error {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No order for this header", "SecMode", s.SecMode)
	}
	copy(s.Metadata()[scmp_auth_extn.ORDER_OFFSET:], order)
	return nil

}

func (s *rSecurityExt) Order() common.RawBytes {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return s.Metadata()[0:0]
	}
	return s.Metadata()[scmp_auth_extn.ORDER_OFFSET:]
}

func (s *rSecurityExt) UpdateSignature(signature common.RawBytes) *common.Error {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No signature for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator()[:scmp_auth_extn.SIGNATURE_LENGTH], signature)
	return nil

}

func (s *rSecurityExt) Signature() common.RawBytes {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return s.Authenticator()[0:0]
	}
	return s.Authenticator()[:scmp_auth_extn.SIGNATURE_LENGTH]
}

func (s *rSecurityExt) UpdateHashes(hashes common.RawBytes) *common.Error {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return common.NewError("No hashes for this header", "SecMode", s.SecMode)
	}
	copy(s.Authenticator()[scmp_auth_extn.SIGNATURE_LENGTH:], hashes)
	return nil

}

func (s *rSecurityExt) Hashes() common.RawBytes {
	if s.SecMode != sec_extn.SCMP_AUTH_HASH_TREE {
		return s.Authenticator()[0:0]
	}
	return s.Authenticator()[scmp_auth_extn.SIGNATURE_LENGTH:]
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
