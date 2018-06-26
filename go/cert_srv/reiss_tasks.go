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

package main

import (
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

// SelfIssuer periodically issues self-signed certificate chains
// on an issuer AS before the old one expires.
type SelfIssuer struct{}

// Run periodically issues certificate chains for the local AS.
func (s *SelfIssuer) Run() {
	if !conf.Get().Topo.Core {
		log.Info("Stopping SelfIssuer on non-issuer CS")
		return
	}
	for {
		var err error
		now := time.Now()
		config := conf.Get()
		issCrt, err := getIssuerCert(config)
		if err != nil {
			log.Crit("Unable to get issuer certificate", "err", err)
			break
		}
		leafCrt := config.Store.GetNewestChain(config.PublicAddr.IA).Leaf
		iSleep := time.Unix(int64(issCrt.ExpirationTime), 0).Sub(now) - config.IssuerReissTime
		lSleep := time.Unix(int64(leafCrt.ExpirationTime), 0).Sub(now) - config.LeafReissTime
		if lSleep > 0 && iSleep > 0 {
			if iSleep < lSleep {
				time.Sleep(iSleep)
			} else {
				time.Sleep(lSleep)
			}
			continue
		}
		if iSleep > 0 {
			if err = s.createLeafCert(leafCrt, config); err != nil {
				log.Error("Unable to issue certificate chain", "err", err)
				time.Sleep(config.ReissRate)
				continue
			}
		} else {
			if err = s.createIssuerCert(config); err != nil {
				log.Error("Unable to create issuer certificate", "err", err)
				time.Sleep(config.ReissRate)
				continue
			}
		}
	}
}

// createLeafCert creates a leaf certificate.
func (s *SelfIssuer) createLeafCert(leaf *cert.Certificate, config *conf.Conf) error {
	issCrt, err := getIssuerCert(config)
	if err != nil {
		return nil
	}
	chain := &cert.Chain{Leaf: leaf.Copy(), Issuer: issCrt}
	chain.Leaf.Version += 1
	chain.Leaf.IssuingTime = uint64(time.Now().Unix())
	chain.Leaf.CanIssue = false
	chain.Leaf.ExpirationTime = chain.Leaf.IssuingTime + cert.DefaultLeafCertValidity
	if chain.Issuer.ExpirationTime < chain.Leaf.ExpirationTime {
		chain.Leaf.ExpirationTime = chain.Issuer.ExpirationTime
	}
	if err := chain.Leaf.Sign(config.GetIssSigningKey(), issCrt.SignAlgorithm); err != nil {
		return common.NewBasicError("Unable to sign leaf certificate", err, "chain", chain)
	}
	if err := config.Store.VerifyChain(config.PublicAddr.IA, chain); err != nil {
		return common.NewBasicError("Unable to verify chain", err, "chain", chain)
	}
	if err := config.Store.AddChain(chain, true); err != nil {
		return common.NewBasicError("Unable to write certificate chain", err, "chain", chain)
	}
	log.Info("Created certificate chain", "chain", chain)
	sign, err := CreateSign(config.PublicAddr.IA, config.Store)
	if err != nil {
		log.Error("Unable to set create new sign", "err", err)
	}
	config.SetSigner(ctrl.NewBasicSigner(sign, config.GetSigningKey()))
	return nil
}

// createIssuerCert creates an issuer certificate.
func (s *SelfIssuer) createIssuerCert(config *conf.Conf) error {
	crt, err := getIssuerCert(config)
	if err != nil {
		return err
	}
	crt.Version += 1
	crt.IssuingTime = uint64(time.Now().Unix())
	crt.CanIssue = true
	crt.ExpirationTime = crt.IssuingTime + cert.DefaultIssuerCertValidity
	coreAS, err := s.getCoreASEntry(config)
	if err != nil {
		return common.NewBasicError("Unable to get core AS entry", err, "cert", crt)
	}
	if err = crt.Sign(config.GetOnRootKey(), coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError("Unable to sign issuer certificate", err, "cert", crt)
	}
	if err = crt.Verify(crt.Issuer, coreAS.OnlineKey, coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError("Invalid issuer certificate signature", err, "cert", crt)
	}
	if err = setIssuerCert(crt, config); err != nil {
		return common.NewBasicError("Unable to store issuer certificate", err, "cert", crt)
	}
	log.Info("Created issuer certificate", "cert", crt)
	return nil
}

func (s *SelfIssuer) getCoreASEntry(config *conf.Conf) (*trc.CoreAS, error) {
	maxTrc := config.Store.GetNewestTRC(config.PublicAddr.IA.I)
	if maxTrc == nil {
		return nil, common.NewBasicError("Unable to find local TRC", nil)
	}
	coreAS := maxTrc.CoreASes[config.PublicAddr.IA]
	if coreAS == nil {
		return nil, common.NewBasicError("Local AS is not a core AS in the max TRC",
			nil, "maxTrc", maxTrc)
	}
	return coreAS, nil
}

func getIssuerCert(config *conf.Conf) (*cert.Certificate, error) {
	issCrt, err := config.TrustDB.GetIssCertMaxVersion(config.PublicAddr.IA)
	if err != nil {
		return nil, err
	}
	if issCrt == nil {
		return nil, common.NewBasicError("Issuer certificate not found", nil,
			"ia", config.PublicAddr.IA)
	}
	return issCrt, nil
}

func setIssuerCert(crt *cert.Certificate, config *conf.Conf) error {
	affected, err := config.TrustDB.InsertIssCert(crt)
	if err != nil {
		return err
	}
	if affected == 0 {
		return common.NewBasicError("Issuer certificate already exists", nil, "cert", crt)
	}
	return nil
}

// ReissRequester periodically requests reissued certificate chains before
// expiration of the currently active certificate chain.
type ReissRequester struct {
	conn *snet.Conn
	stop chan struct{}
}

func NewReissRequester(conn *snet.Conn) *ReissRequester {
	return &ReissRequester{
		conn: conn,
		stop: make(chan struct{}),
	}
}

// Run periodically requests reissued certificate chains from the issuer AS.
func (r *ReissRequester) Run() {
	if conf.Get().Topo.Core {
		log.Info("Stopping ReissRequester on issuer CS")
		return
	}
	for {
		select {
		case <-r.stop:
			return
		default:
			config := conf.Get()
			chain := config.Store.GetNewestChain(config.PublicAddr.IA)
			now := time.Now()
			exp := util.USecsToTime(chain.Leaf.ExpirationTime)
			diff := exp.Sub(now)
			if diff < 0 {
				log.Error("Certificate expired without being reissued", "ExpirationTime",
					util.TimeToString(exp), "now", util.TimeToString(now))
				return
			}
			if sleep := diff - config.LeafReissTime; sleep > 0 {
				time.Sleep(sleep)
				continue
			}
			if err := r.sendReq(chain, config); err != nil {
				log.Error("Unable to send certificate reissue request", "err", err)
			}
			time.Sleep(config.ReissRate)
		}
	}
}

// sendReq creates and sends a certificate chain reissue request based on the newest
// currently active certificate chain.
func (r *ReissRequester) sendReq(chain *cert.Chain, config *conf.Conf) error {
	c := chain.Leaf.Copy()
	c.IssuingTime = uint64(time.Now().Unix())
	c.ExpirationTime = c.IssuingTime + (chain.Leaf.ExpirationTime - chain.Leaf.IssuingTime)
	c.Version += 1
	if err := c.Sign(config.GetSigningKey(), chain.Leaf.SignAlgorithm); err != nil {
		return err
	}
	raw, err := c.JSON(false)
	if err != nil {
		return err
	}
	req := &cert_mgmt.ChainIssReq{RawCert: raw}
	cpld, err := ctrl.NewCertMgmtPld(&cert_mgmt.ChainIssReq{RawCert: raw}, nil, nil)
	if err != nil {
		return err
	}
	a := &snet.Addr{IA: c.Issuer, Host: addr.SvcCS}
	log.Debug("Send certificate reissue request", "req", req, "addr", a)
	return SendSignedPayload(r.conn, cpld, a, config)
}

// Close terminates the ReissRequester.
func (r *ReissRequester) Close() {
	close(r.stop)
}
