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

package main

import (
	"math/rand"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/go/lib/periodic"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/infraenv"

	"github.com/scionproto/scion/go/cert_srv/internal/csconfig"
	"github.com/scionproto/scion/go/cert_srv/internal/reiss"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
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

// initConfig initialize the config. CurrMsgr and reissTask are set.
func initConfig(config *Config) error {
	var err error
	if err = config.CS.Init(config.General.ConfigDir); err != nil {
		return common.NewBasicError("Unable to initialize CS config", err)
	}
	if err = initState(config); err != nil {
		return err
	}
	var reissHandler *reiss.Handler
	if config.General.Topology.Core {
		reissHandler = &reiss.Handler{
			State: config.state,
			IA:    config.General.Topology.ISD_AS,
		}
	}
	if currMsgr, err = startMessenger(config, reissHandler); err != nil {
		return err
	}
	reissRunner = startReissRunner(config, currMsgr)
	return nil
}

// initState sets the state.
func initState(config *Config) error {
	var err error
	config.state, err = csconfig.LoadState(config.General.ConfigDir, config.General.Topology.Core)
	if err != nil {
		return common.NewBasicError("Unable to load CS state", err)
	}
	if config.state.TrustDB, err = trustdb.New(config.Trust.TrustDB); err != nil {
		return common.NewBasicError("Unable to initialize trustDB", err)
	}
	trustConf := &trust.Config{
		MustHaveLocalChain: true,
		IsCS:               true,
	}
	config.state.Store, err = trust.NewStore(config.state.TrustDB, config.General.Topology.ISD_AS,
		rand.Uint64(), trustConf, log.Root())
	if err != nil {
		return common.NewBasicError("Unable to initialize trust store", err)
	}
	err = config.state.Store.LoadAuthoritativeTRC(filepath.Join(config.General.ConfigDir, "certs"))
	if err != nil {
		return common.NewBasicError("Unable to load local TRC", err)
	}
	err = config.state.Store.LoadAuthoritativeChain(
		filepath.Join(config.General.ConfigDir, "certs"))
	if err != nil {
		return common.NewBasicError("Unable to load local Chain", err)
	}
	if err = setDefaultSignerVerifier(config.state, config.General.Topology.ISD_AS); err != nil {
		return common.NewBasicError("Unable to set default signer and verifier", err)
	}
	return nil
}

// setDefaultSignerVerifier sets the signer and verifier. The newest certificate chain version
// in the store is used.
func setDefaultSignerVerifier(c *csconfig.State, pubIA addr.IA) error {
	sign, err := trust.CreateSign(pubIA, c.Store)
	if err != nil {
		return err
	}
	c.SetSigner(ctrl.NewBasicSigner(sign, c.GetSigningKey()))
	c.SetVerifier(ctrl.NewBasicSigVerifier(c.Store))
	return nil
}

// startMessenger starts the messenger and sets the internal messenger of the store in
// config.CS. This function may only be called once per config.
func startMessenger(config *Config, reissHandler *reiss.Handler) (*messenger.Messenger, error) {

	if config.General.Topology.Core != (reissHandler != nil) {
		return nil, common.NewBasicError("ReissHandler does not match topology", nil,
			"core", config.General.Topology.Core, "reissHandler", reissHandler != nil)
	}
	topoAddress := config.General.Topology.CS.GetById(config.General.ID)
	if topoAddress == nil {
		return nil, common.NewBasicError("Unable to find topo address", nil)
	}
	msgrI, err := infraenv.InitMessengerWithSciond(
		config.General.Topology.ISD_AS,
		env.GetPublicSnetAddress(config.General.Topology.ISD_AS, topoAddress),
		env.GetBindSnetAddress(config.General.Topology.ISD_AS, topoAddress),
		addr.SvcCS,
		config.General.ReconnectToDispatcher,
		config.state.Store,
		config.Sciond,
	)
	// XXX(roosd): Hack to make Store.ChooseServer not panic.
	snet.Init(config.General.Topology.ISD_AS, config.Sciond.Path, "")
	if err != nil {
		return nil, common.NewBasicError("Unable to initialize SCION Messenger", err)
	}
	// We need the actual type to set the signer and verifier.
	msgr, ok := msgrI.(*messenger.Messenger)
	if !ok {
		return nil, common.NewBasicError("Unsupported messenger type", nil, "msgrI", msgrI)
	}
	msgr.AddHandler(infra.ChainRequest, config.state.Store.NewChainReqHandler(true))
	msgr.AddHandler(infra.TRCRequest, config.state.Store.NewTRCReqHandler(true))
	msgr.AddHandler(infra.Chain, config.state.Store.NewChainPushHandler())
	msgr.AddHandler(infra.TRC, config.state.Store.NewTRCPushHandler())
	if config.General.Topology.Core {
		msgr.AddHandler(infra.ChainIssueRequest, reissHandler)
	}
	msgr.UpdateSigner(config.state.GetSigner(), []infra.MessageType{infra.ChainIssueRequest})
	msgr.UpdateVerifier(config.state.GetVerifier())
	go func() {
		defer log.LogPanicAndExit()
		msgr.ListenAndServe()
	}()
	return msgr, nil
}

func startReissRunner(config *Config, msgr *messenger.Messenger) *periodic.Runner {
	if config.General.Topology.Core {
		log.Info("Starting periodic reiss.Self task")
		return periodic.StartPeriodicTask(
			&reiss.Self{
				Msgr:     msgr,
				State:    config.state,
				IA:       config.General.Topology.ISD_AS,
				IssTime:  config.CS.IssuerReissueTime.Duration,
				LeafTime: config.CS.LeafReissueTime.Duration,
			},
			time.NewTicker(config.CS.ReissueRate.Duration),
			config.CS.ReissueTimeout.Duration,
		)
	}
	log.Info("Starting periodic reiss.Requester task")
	return periodic.StartPeriodicTask(
		&reiss.Requester{
			Msgr:     msgr,
			State:    config.state,
			IA:       config.General.Topology.ISD_AS,
			LeafTime: config.CS.LeafReissueTime.Duration,
		},
		time.NewTicker(config.CS.ReissueRate.Duration),
		config.CS.ReissueTimeout.Duration,
	)
}
