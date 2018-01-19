// Copyright 2018 ETH Zurich
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

package paths

import (
	"context"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
)

type PathVerifier struct {
	trustStore *trust.Store
}

func NewPathVerifier(store *trust.Store) *PathVerifier {
	return &PathVerifier{
		trustStore: store,
	}
}

// VerifySegReply uses the trust store to verify a path segment.
//
// Note: PoC for now, missing tests and some of the logic.
func (pv *PathVerifier) VerifySegReply(ctx context.Context, reply *path_mgmt.SegReply) error {
	segRecords := reply.Recs
	for _, pathSegMeta := range segRecords.Recs {
		pathSegment := pathSegMeta.Segment
		asEntry := pathSegment.ASEntries[0]
		trail := []trust.TrustDescriptor{
			{
				TRCVersion:   asEntry.TrcVer,
				ChainVersion: asEntry.CertVer,
				IA:           *asEntry.IA(),
				Type:         trust.ChainDescriptor,
			},
		}
		for idx, asEntry := range pathSegment.ASEntries {
			// XXX(scrye): Additional logic is needed to build a trust trail
			// for down segments in remote ISDs.
			descriptor := trust.TrustDescriptor{
				TRCVersion:   asEntry.TrcVer,
				ChainVersion: asEntry.CertVer,
				IA:           *asEntry.IA(),
				Type:         trust.TRCDescriptor,
			}
			trail = prepend(trail, descriptor)
			certificate, err := pv.trustStore.GetCertificate(ctx, trail, nil)
			if err != nil {
				return common.NewBasicError("Unable to fetch signer certificate", err)
			}
			if err := pathSegment.VerifyASEntry(certificate.SubjectSignKey, idx); err != nil {
				// Verification of ASEntry at index idx failed
				return common.NewBasicError("Unable to verify ASEntry", err, "idx", idx)
			}
		}
	}
	return nil
}

func prepend(slice []trust.TrustDescriptor, elem trust.TrustDescriptor) []trust.TrustDescriptor {
	return append([]trust.TrustDescriptor{elem}, slice...)
}
