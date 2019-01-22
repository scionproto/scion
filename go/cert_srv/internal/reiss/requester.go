// Copyright 2018 ETH Zurich, Anapaya Systems
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

package reiss

import (
	"bytes"
	"context"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

var _ periodic.Task = (*Requester)(nil)

// Requester requests reissued certificate chains before
// expiration of the currently active certificate chain.
type Requester struct {
	Msgr     infra.Messenger
	State    *config.State
	IA       addr.IA
	LeafTime time.Duration
}

// Run requests reissued certificate chains from the issuer AS.
func (r *Requester) Run(ctx context.Context) {
	crit, err := r.run(ctx)
	switch {
	case crit && err != nil:
		log.Crit("[reiss.Requester] Unable to get reissued certificate chain", "err", err)
	case err != nil:
		log.Error("[reiss.Requester] Unable to get reissued certificate chain", "err", err)
	}
}

func (r *Requester) run(ctx context.Context) (bool, error) {
	chain, err := r.State.Store.GetChain(ctx, r.IA, scrypto.LatestVer)
	if err != nil {
		return true, common.NewBasicError("Unable to get local certificate chain", err)
	}
	exp := util.SecsToTime(chain.Leaf.ExpirationTime)
	now := time.Now()
	if now.After(exp) {
		return true, common.NewBasicError("Certificate expired without being reissued", nil,
			"chain", chain, "expTime", util.TimeToString(exp), "now", util.TimeToString(now))
	}
	if now.Add(r.LeafTime).Before(exp) {
		return false, nil
	}
	return r.sendReq(ctx, chain)
}

// sendReq creates and sends a certificate chain reissue request based on the newest
// currently active certificate chain.
func (r *Requester) sendReq(ctx context.Context, chain *cert.Chain) (bool, error) {
	c := chain.Leaf.Copy()
	c.IssuingTime = util.TimeToSecs(time.Now())
	c.ExpirationTime = c.IssuingTime + (chain.Leaf.ExpirationTime - chain.Leaf.IssuingTime)
	c.Version++
	if err := c.Sign(r.State.GetSigningKey(), chain.Leaf.SignAlgorithm); err != nil {
		return true, common.NewBasicError("Unable to sign certificate", err)
	}
	raw, err := c.JSON(false)
	if err != nil {
		return false, common.NewBasicError("Unable to pack certificate", err)
	}
	req := &cert_mgmt.ChainIssReq{RawCert: raw}
	a := &snet.Addr{IA: c.Issuer, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	rep, err := r.Msgr.RequestChainIssue(ctx, req, a, messenger.NextId())
	if err != nil {
		return false, common.NewBasicError("Unable to request reissued certificate chain", err)
	}
	log.Trace("[reiss.Requester] Received certificate reissue reply", "addr", a, "rep", rep)
	if crit, err := r.handleRep(ctx, rep); err != nil {
		return crit, common.NewBasicError("Unable to handle reply", err, "addr", a, "rep", rep)
	}
	return false, nil
}

func (r *Requester) handleRep(ctx context.Context, rep *cert_mgmt.ChainIssRep) (bool, error) {
	chain, err := rep.Chain()
	if err != nil {
		return false, common.NewBasicError("Unable to parse chain", err)
	}
	if err = r.validateRep(ctx, chain); err != nil {
		return true, common.NewBasicError("Unable to validate chain", err, "chain", chain)
	}
	if _, err = r.State.TrustDB.InsertChain(ctx, chain); err != nil {
		return true, common.NewBasicError("Unable to insert reissued certificate chain in TrustDB",
			err, "chain", chain)
	}
	sign, err := trust.CreateSign(r.IA, r.State.Store)
	if err != nil {
		return true, common.NewBasicError("Unable to set new signer", err)
	}
	signer := trust.NewBasicSigner(sign, r.State.GetSigningKey())
	r.State.SetSigner(signer)
	r.Msgr.UpdateSigner(signer, []infra.MessageType{infra.ChainIssueRequest})
	log.Info("[reiss.Requester] Updated certificate chain", "chain", chain)
	return false, nil
}

// validateRep validates that the received certificate chain can be added to the trust store.
func (r *Requester) validateRep(ctx context.Context, chain *cert.Chain) error {
	verKey := common.RawBytes(ed25519.PrivateKey(
		r.State.GetSigningKey()).Public().(ed25519.PublicKey))
	if !bytes.Equal(chain.Leaf.SubjectSignKey, verKey) {
		return common.NewBasicError("Invalid SubjectSignKey", nil, "expected",
			verKey, "actual", chain.Leaf.SubjectSignKey)
	}
	// FIXME(roosd): validate SubjectEncKey
	chain, err := r.State.Store.GetChain(ctx, r.IA, scrypto.LatestVer)
	if err != nil {
		return err
	}
	issuer := chain.Leaf.Issuer
	if !chain.Leaf.Issuer.Equal(issuer) {
		return common.NewBasicError("Invalid Issuer", nil, "expected",
			issuer, "actual", chain.Leaf.Issuer)
	}
	return trust.VerifyChain(r.IA, chain, r.State.Store)
}
