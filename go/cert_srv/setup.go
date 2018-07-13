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

package main

import (
	"time"

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	ErrorConf      = "Unable to load configuration"
	ErrorDispClose = "Unable to close dispatcher"
	ErrorDispInit  = "Unable to initialize dispatcher"
	ErrorSign      = "Unable to create sign"
	ErrorSNET      = "Unable to create local SCION Network context"
)

// setup loads and sets the newest configuration. If needed, the
// snet/dispatcher are initialized.
//
// FIXME(scrye): Reloading is currently disabled, so this function is currently
// only called once.
func setup() error {
	oldConf := conf.Get()
	newConf, err := loadConf(oldConf)
	if err != nil {
		return common.NewBasicError(ErrorConf, err)
	}
	// Set signer and verifier
	if err = setDefaultSignerVerifier(newConf); err != nil {
		return common.NewBasicError(ErrorSign, err)
	}
	// Set the new configuration.
	conf.Set(newConf)

	// Initialize infra messaging stack if not already initialized
	if oldConf == nil {
		return setupNewConf(newConf)
	}
	return nil
}

func setupNewConf(newConf *conf.Conf) error {
	var err error
	if err = initSNET(newConf.PublicAddr.IA, initAttempts, initInterval); err != nil {
		return common.NewBasicError(ErrorSNET, err)
	}
	conn, err := snet.ListenSCIONWithBindSVC("udp4", newConf.PublicAddr, newConf.BindAddr,
		addr.SvcCS)
	if err != nil {
		return err
	}
	msger := messenger.New(
		newConf.Topo.ISD_AS,
		disp.New(
			transport.NewPacketTransport(conn),
			messenger.DefaultAdapter,
			log.Root(),
		),
		newConf.Store,
		log.Root(),
		nil,
	)
	newConf.Store.SetMessenger(msger)
	msger.AddHandler(infra.ChainRequest, newConf.Store.NewChainReqHandler(true))
	msger.AddHandler(infra.TRCRequest, newConf.Store.NewTRCReqHandler(true))
	msger.AddHandler(infra.Chain, newConf.Store.NewChainPushHandler())
	msger.AddHandler(infra.TRC, newConf.Store.NewTRCPushHandler())
	msger.AddHandler(infra.ChainIssueRequest, &ReissHandler{})
	msger.UpdateSigner(newConf.GetSigner(), []infra.MessageType{infra.ChainIssueRequest})
	msger.UpdateVerifier(newConf.GetVerifier())
	go func() {
		defer log.LogPanicAndExit()
		msger.ListenAndServe()
	}()
	if newConf.Topo.Core {
		go func() {
			defer log.LogPanicAndExit()
			selfIssuer := NewSelfIssuer(msger)
			selfIssuer.Run()
		}()
	} else {
		go func() {
			defer log.LogPanicAndExit()
			reissRequester := NewReissRequester(msger)
			reissRequester.Run()
		}()
	}
	return nil
}

// loadConf loads the newest configuration.
func loadConf(oldConf *conf.Conf) (*conf.Conf, error) {
	if oldConf != nil {
		return conf.ReloadConf(oldConf)
	}
	return conf.Load(*id, *confDir, *stateDir)
}

// setDefaultSignerVerifier sets the signer and verifier. The newest certificate chain version is
// used.
func setDefaultSignerVerifier(c *conf.Conf) error {
	sign, err := trust.CreateSign(c.PublicAddr.IA, c.Store)
	if err != nil {
		return err
	}
	c.SetSigner(ctrl.NewBasicSigner(sign, c.GetSigningKey()))
	c.SetVerifier(ctrl.NewBasicSigVerifier(c.Store))
	return nil
}

// initSNET initializes snet. The number of attempts is specified, as well as the sleep duration.
// This is needed, since supervisord might take some time, until sciond is initialized.
func initSNET(ia addr.IA, attempts int, sleep time.Duration) (err error) {
	// Initialize SCION local networking module
	for i := 0; i < attempts; i++ {
		if err = snet.Init(ia, *sciondPath, *dispPath); err == nil {
			break
		}
		log.Error("Unable to initialize snet", "Retry interval", sleep, "err", err)
		time.Sleep(sleep)
	}
	return err
}
