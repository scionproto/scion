// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package trust

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/util"
)

// FIXME(scrye): Reconsider whether these functions should access the trust
// store directly, as that means propagating the context all the way here.
// Callers already know what crypto is needed, so they can pass it in.

func CreateSignMeta(ctx context.Context, ia addr.IA,
	trustDB trustdb.TrustDB) (infra.SignerMeta, error) {

	meta := infra.SignerMeta{}
	c, err := trustDB.GetChainMaxVersion(ctx, ia)
	if err != nil {
		return meta, common.NewBasicError("Unable to find local certificate chain", err)
	}
	t, err := trustDB.GetTRCMaxVersion(ctx, ia.I)
	if err != nil {
		return meta, common.NewBasicError("Unable to find local TRC", err)
	}
	meta = infra.SignerMeta{
		Algo: c.Leaf.SignAlgorithm,
		Src: ctrl.SignSrcDef{
			IA:       ia,
			ChainVer: c.Leaf.Version,
			TRCVer:   t.Version,
		},
		ExpTime: util.SecsToTime(c.Leaf.ExpirationTime),
	}
	return meta, nil
}

// VerifyChain verifies the chain based on the TRCs present in the store.
func VerifyChain(ctx context.Context, subject addr.IA, chain *cert.Chain,
	store infra.TrustStore) error {

	maxTrc, err := store.GetValidTRC(ctx, chain.Issuer.Issuer.I, nil)
	if err != nil {
		return common.NewBasicError("Unable to find TRC", nil, "isd", chain.Issuer.Issuer.I)
	}
	if err := maxTrc.IsActive(maxTrc); err != nil {
		return common.NewBasicError("Newest TRC not active", err)
	}
	if err := chain.Verify(subject, maxTrc); err != nil {
		var graceTrc *trc.TRC
		if maxTrc.Version > 1 {
			graceTrc, err = store.GetTRC(ctx, maxTrc.ISD, maxTrc.Version-1)
			if err != nil {
				return err
			}
		}
		if graceTrc == nil || graceTrc.IsActive(maxTrc) != nil {
			return common.NewBasicError("Unable to verify chain", err)
		}
		if chain.Issuer.TRCVersion <= graceTrc.Version &&
			common.GetErrorMsg(err) == cert.IssCertInvalid {

			if errG := chain.Verify(subject, graceTrc); errG != nil {
				return common.NewBasicError("Unable to verify chain", err, "errGraceTRC", errG)
			}
		} else {
			return common.NewBasicError("Unable to verify chain", err)
		}
	}
	return nil
}

func GetChainForSign(ctx context.Context, src ctrl.SignSrcDef,
	store infra.TrustStore, server net.Addr) (*cert.Chain, error) {

	return store.GetValidChain(ctx, src.IA, src.ChainVer, server)
}
