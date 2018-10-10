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

	"github.com/scionproto/scion/go/cert_srv/internal/csconfig"
	"github.com/scionproto/scion/go/cert_srv/internal/handlers"
	"github.com/scionproto/scion/go/cert_srv/internal/periodic"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
)

const (
	ErrorConf      = "Unable to load configuration"
	ErrorDispClose = "Unable to close dispatcher"
	ErrorDispInit  = "Unable to initialize dispatcher"
	ErrorSign      = "Unable to create sign"
	ErrorSNET      = "Unable to create local SCION Network context"
)

// setConfig set initializes the new config based on the old one. The currMsgr
// and reissTask are updated accordingly.
//
// FIXME(roosd): Reloading is currently disabled, this is only called with nil oldConf.
func setConfig(newConf, oldConf *Config) error {
	if oldConf == nil {
		return setNewConfig(newConf)
	}
	return setReloadedConfig(newConf, oldConf)
}

func setReloadedConfig(newConf, oldConf *Config) error {
	// FIXME(roosd): Following must be reloaded if necessary:
	//  - messenger
	//  - trustdb/store
	//  - reissTask
	return common.NewBasicError("Config reload not implemented", nil)
}

// setNewConfig initialize the first config. CurrMsgr and reissTask are set.
func setNewConfig(config *Config) error {
	var err error
	if err = initNewConf(config); err != nil {
		return err
	}
	var reissHandler *handlers.ReissHandler
	if config.General.Topology.Core {
		reissHandler = &handlers.ReissHandler{
			State: config.state,
			IA:    config.General.Topology.ISD_AS,
		}
	}
	if currMsgr, err = startMessenger(config, reissHandler); err != nil {
		return err
	}
	reissTask = startTask(config, currMsgr)
	return nil
}

// initNewConf sets the CS field of config.
func initNewConf(config *Config) error {
	var err error
	if err = config.CS.Init(config.General.ConfigDir); err != nil {
		return common.NewBasicError("Unable to initialize CS config", err)
	}
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
func startMessenger(config *Config,
	reissHandler *handlers.ReissHandler) (*messenger.Messenger, error) {

	if config.General.Topology.Core != (reissHandler != nil) {
		return nil, common.NewBasicError("ReissHandler does not match topology", nil,
			"core", config.General.Topology.Core, "reissHandler", reissHandler != nil)
	}
	topoAddress := config.General.Topology.CS.GetById(config.General.ID)
	if topoAddress == nil {
		return nil, common.NewBasicError("Unable to find topo address", nil)
	}
	// InitMessenger sets the messenger of the store automatically.
	msgr, err := initMessenger(
		config,
		env.GetPublicSnetAddress(config.General.Topology.ISD_AS, topoAddress),
		env.GetBindSnetAddress(config.General.Topology.ISD_AS, topoAddress),
	)
	if err != nil {
		return nil, common.NewBasicError("Unable to initialize SCION Messenger", err)
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

func initMessenger(config *Config, public, bind *snet.Addr) (*messenger.Messenger, error) {
	conn, err := initNetworking(config, public, bind)
	if err != nil {
		return nil, err
	}
	msgr := messenger.New(
		config.General.Topology.ISD_AS,
		disp.New(
			transport.NewPacketTransport(conn),
			messenger.DefaultAdapter,
			log.Root(),
		),
		config.state.Store,
		log.Root(),
		nil,
	)
	config.state.Store.SetMessenger(msgr)
	return msgr, nil
}

func initNetworking(config *Config, public, bind *snet.Addr) (snet.Conn, error) {
	var network snet.Network
	network, err := initNetwork(config)
	if err != nil {
		return nil, common.NewBasicError("Unable to create network", err)
	}
	if snet.DefNetwork == nil {
		// XXX(roosd): Hack to make Store.ChooseServer not panic.
		snet.InitWithNetwork(network.(*snet.SCIONNetwork))
	}
	if config.General.ReconnectToDispatcher {
		network = snetproxy.NewProxyNetwork(network)
	}
	conn, err := network.ListenSCIONWithBindSVC("udp4", public, bind, addr.SvcCS, 5*time.Second)
	if err != nil {
		return nil, common.NewBasicError("Unable to listen on SCION", err)
	}
	return conn, nil
}

func initNetwork(config *Config) (*snet.SCIONNetwork, error) {
	var err error
	var network *snet.SCIONNetwork
	timeout := time.Now().Add(config.CS.SciondTimeout.Duration)
	for time.Now().Before(timeout) {
		network, err = snet.NewNetwork(config.General.Topology.ISD_AS, config.CS.SciondPath, "")
		if err == nil {
			break
		}
		log.Error("Unable to initialize network",
			"Retry interval", config.CS.SciondRetryInterval, "err", err)
		time.Sleep(config.CS.SciondRetryInterval.Duration)
	}
	return network, err
}

func startTask(config *Config, msgr *messenger.Messenger) task {
	if config.General.Topology.Core {
		selfIssuer := periodic.NewSelfIssuer(msgr, config.state, config.General.Topology.ISD_AS,
			config.CS.IssuerReissueTime.Duration, config.CS.LeafReissueTime.Duration,
			config.CS.ReissueRate.Duration)
		go selfIssuer.Run()
		return selfIssuer
	}
	reissRequester := periodic.NewReissRequester(msgr, config.state,
		config.General.Topology.ISD_AS, config.CS.LeafReissueTime.Duration,
		config.CS.ReissueRate.Duration, config.CS.ReissueTimeout.Duration)
	go reissRequester.Run()
	return reissRequester
}
