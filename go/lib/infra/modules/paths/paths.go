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
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
)

type Verifier struct {
	trustStore *trust.Store
}

func NewVerifier(store *trust.Store) *Verifier {
	return &Verifier{
		trustStore: store,
	}
}

// VerifySegReply uses the trust store to verify a path segment.
//
// Note: PoC for now, missing tests and some of the logic.
func (pv *Verifier) VerifyPaths(ctx context.Context, reply *path_mgmt.SegReply) error {
	// TODO(scrye): Probably this needs to be changed to be more fine-graind
	// (i.e., return the paths that were verified, and return the paths where
	// verification failed.
	segRecords := reply.Recs
	for _, pathSegMeta := range segRecords.Recs {
		err := pv.VerifyPathSegment(ctx, pathSegMeta.Segment)
		if err != nil {
			return err
		}
	}
	return nil
}

func (pv *Verifier) VerifyPathSegment(ctx context.Context, segment seg.PathSegment) error {
	// Start from the last signature (over all the entries in the segment), and
	// go towards the first one.
	for i := len(segment.ASEntries) - 1; i >= 0; i-- {
		trail := pv.buildTrustTrail(segment.ASEntries[i:])
		certificate, err := pv.trustStore.GetCertificate(ctx, trail, nil)
		if err != nil {
			return common.NewBasicError("Unable to fetch signer certificate", err)
		}
		if err := segment.VerifyASEntry(certificate.SubjectSignKey, i); err != nil {
			// Verification of ASEntry at index idx failed
			return common.NewBasicError("Unable to verify ASEntry", err, "index", i)
		}
	}
	return nil
}

// buildTrustTrail extracts the sequence of trust descriptors required to
// verify the bottom signature in entries.
func (pv *Verifier) buildTrustTrail(entries []*seg.ASEntry) []trust.Descriptor {
	if entries == nil {
		return nil
	}
	// The bottom signature is contained in the first entry.
	firstEntry := entries[0]
	trail := []trust.Descriptor{
		{
			TRCVersion:   firstEntry.TrcVer,
			ChainVersion: firstEntry.CertVer,
			IA:           *firstEntry.IA(),
			Type:         trust.ChainDescriptor,
		},
	}
	// Add TRCs for each AS entry starting from the first entry itself. This
	// constructs the ISD trail from the ISD of the bottom signer, to the ISD
	// of the top signer. The top signer will usually be a very close ISD,
	// either the local one or a direct neighbor.
	for _, asEntry := range entries {
		desc := trust.Descriptor{
			TRCVersion:   asEntry.TrcVer,
			ChainVersion: asEntry.CertVer,
			IA:           *asEntry.IA(),
			Type:         trust.TRCDescriptor,
		}
		trail = append(trail, desc)
	}
	return trail
}
