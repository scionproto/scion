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
	"context"
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/util"
)

var _ periodic.Task = (*Self)(nil)

// Self periodically issues self-signed certificate chains
// on an issuer AS before the old one expires.
type Self struct {
	// Msgr is used to propagate key updates to the messenger, and not for network traffic
	Msgr     infra.Messenger
	State    *config.State
	IA       addr.IA
	IssTime  time.Duration
	LeafTime time.Duration
}

// Run issues certificate chains for the local AS.
func (s *Self) Run(ctx context.Context) {
	if err := s.run(ctx); err != nil {
		log.Crit("[reiss.Self] Unable to self issue", "err", err)
	}
}

func (s *Self) run(ctx context.Context) error {
	issCrt, err := s.getIssuerCert(ctx)
	if err != nil {
		return common.NewBasicError("Unable to get issuer certificate", err)
	}
	chain, err := s.State.Store.GetChain(ctx, s.IA, scrypto.LatestVer)
	if err != nil {
		return common.NewBasicError("Unable to get certificate chain", err)
	}
	now := time.Now()
	iSleep := time.Unix(int64(issCrt.ExpirationTime), 0).Sub(now) - s.IssTime
	lSleep := time.Unix(int64(chain.Leaf.ExpirationTime), 0).Sub(now) - s.LeafTime
	if lSleep > 0 && iSleep > 0 {
		return nil
	}
	if iSleep <= 0 {
		// The issuer certificated needs to be updated.
		if err = s.createIssuerCert(ctx, issCrt); err != nil {
			return common.NewBasicError("Unable to create issuer certificate", err)
		}
	}
	if lSleep <= 0 {
		if err = s.createLeafCert(ctx, chain.Leaf); err != nil {
			return common.NewBasicError("Unable to issue certificate chain", err)
		}
	}
	return nil
}

// createLeafCert creates a leaf certificate.
func (s *Self) createLeafCert(ctx context.Context, leaf *cert.Certificate) error {
	issCrt, err := s.getIssuerCert(ctx)
	if err != nil {
		return common.NewBasicError("Unable to get issuer certificate", err)
	}
	chain := &cert.Chain{Leaf: leaf.Copy(), Issuer: issCrt}
	chain.Leaf.Version++
	chain.Leaf.IssuingTime = util.TimeToSecs(time.Now())
	chain.Leaf.CanIssue = false
	chain.Leaf.ExpirationTime = chain.Leaf.IssuingTime + cert.DefaultLeafCertValidity
	if chain.Issuer.ExpirationTime < chain.Leaf.ExpirationTime {
		chain.Leaf.ExpirationTime = chain.Issuer.ExpirationTime
	}
	if err := chain.Leaf.Sign(s.State.GetIssSigningKey(), issCrt.SignAlgorithm); err != nil {
		return common.NewBasicError("Unable to sign leaf certificate", err, "chain", chain)
	}
	if err := trust.VerifyChain(s.IA, chain, s.State.Store); err != nil {
		return common.NewBasicError("Unable to verify chain", err, "chain", chain)
	}
	if _, err := s.State.TrustDB.InsertChain(ctx, chain); err != nil {
		return common.NewBasicError("Unable to write certificate chain", err, "chain", chain)
	}
	log.Info("[reiss.Self] Created certificate chain", "chain", chain)
	sign, err := trust.CreateSign(s.IA, s.State.Store)
	if err != nil {
		log.Error("[reiss.Self] Unable to set create new sign", "err", err)
	}
	signer := trust.NewBasicSigner(sign, s.State.GetSigningKey())
	s.State.SetSigner(signer)
	s.Msgr.UpdateSigner(signer, []infra.MessageType{infra.ChainIssueReply})
	return nil
}

func (s *Self) getIssuerCert(ctx context.Context) (*cert.Certificate, error) {
	issCrt, err := s.State.TrustDB.GetIssCertMaxVersion(ctx, s.IA)
	if err != nil {
		return nil, err
	}
	if issCrt == nil {
		return nil, common.NewBasicError("Issuer certificate not found", nil, "ia", s.IA)
	}
	return issCrt, nil
}

// createIssuerCert creates an issuer certificate.
func (s *Self) createIssuerCert(ctx context.Context, crt *cert.Certificate) error {
	crt = crt.Copy()
	crt.Version += 1
	crt.IssuingTime = util.TimeToSecs(time.Now())
	crt.CanIssue = true
	crt.ExpirationTime = crt.IssuingTime + cert.DefaultIssuerCertValidity
	coreAS, err := s.getCoreASEntry(ctx)
	if err != nil {
		return common.NewBasicError("Unable to get core AS entry", err, "cert", crt)
	}
	if err = crt.Sign(s.State.GetOnRootKey(), coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError("Unable to sign issuer certificate", err, "cert", crt)
	}
	if err = crt.Verify(crt.Issuer, coreAS.OnlineKey, coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError("Invalid issuer certificate signature", err, "cert", crt)
	}
	if err = s.setIssuerCert(ctx, crt); err != nil {
		return common.NewBasicError("Unable to store issuer certificate", err, "cert", crt)
	}
	log.Info("[reiss.Self] Created issuer certificate", "cert", crt)
	return nil
}

func (s *Self) getCoreASEntry(ctx context.Context) (*trc.CoreAS, error) {
	maxTrc, err := s.State.Store.GetTRC(ctx, s.IA.I, scrypto.LatestVer)
	if err != nil {
		return nil, common.NewBasicError("Unable to find local TRC", err)
	}
	coreAS := maxTrc.CoreASes[s.IA]
	if coreAS == nil {
		return nil, common.NewBasicError("Local AS is not a core AS in the max TRC",
			nil, "maxTrc", maxTrc)
	}
	return coreAS, nil
}

func (s *Self) setIssuerCert(ctx context.Context, crt *cert.Certificate) error {
	affected, err := s.State.TrustDB.InsertIssCert(ctx, crt)
	if err != nil {
		return err
	}
	if affected == 0 {
		return common.NewBasicError("Issuer certificate already exists", nil, "cert", crt)
	}
	return nil
}
