// Copyright 2020 ETH Zurich
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

package digest

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/scionproto/scion/go/lib/ctrl/seg/unsigned_extensions/epic_detached"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type Digest []byte

const EpicDigestLength = 16

type DigestExtension struct {
	// Epic dentoes the digest of the EpicDetachedExtension
	Epic Digest
}

func DigestExtensionFromPB(d *cppb.DigestExtension) *DigestExtension {
	if d == nil {
		return nil
	}
	if d.Epic == nil {
		return &DigestExtension{
			Epic: nil,
		}
	}
	if len(d.Epic.Digest) != EpicDigestLength {
		log.Debug("Epic digest: invalid length")
		return &DigestExtension{
			Epic: nil,
		}
	}
	e := make([]byte, EpicDigestLength)
	copy(e, d.Epic.Digest)
	return &DigestExtension{
		Epic: e,
	}
}

func DigestExtensionToPB(d *DigestExtension) *cppb.DigestExtension {
	if d == nil {
		return nil
	}
	if len(d.Epic) != EpicDigestLength {
		log.Debug("Epic digest: invalid length")
		return &cppb.DigestExtension{
			Epic: nil,
		}
	}
	e := make([]byte, EpicDigestLength)
	copy(e, d.Epic)
	return &cppb.DigestExtension{
		Epic: &cppb.DigestExtension_Digest{
			Digest: e,
		},
	}
}

func CalcEpicDigest(ed *epic_detached.EpicDetached) ([]byte, error) {
	if ed == nil {
		return nil, serrors.New("input to CalcEpicDigest must not be nil")
	}
	if len(ed.AuthHopEntry) != epic_detached.AuthLen {
		return nil, serrors.New("authenticator for hop entry has wrong length",
			"len(ed.AuthHopEntry)", len(ed.AuthHopEntry))
	}
	var totalLen uint64 = uint64(1 + len(ed.AuthPeerEntries))
	totalLenAsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(totalLenAsBytes, uint64(totalLen))
	h := sha256.New()
	h.Write(totalLenAsBytes)
	h.Write(ed.AuthHopEntry)

	for _, peer := range ed.AuthPeerEntries {
		if len(peer) != epic_detached.AuthLen {
			return nil, serrors.New("authenticator for peer entry has wrong length",
				"len(peer)", len(peer))
		}
		h.Write(peer)
	}
	return h.Sum(nil)[0:EpicDigestLength], nil
}
