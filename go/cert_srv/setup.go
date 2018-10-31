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

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/cert_srv/internal/csconfig"
	"github.com/scionproto/scion/go/cert_srv/internal/reiss"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

const (
	ErrorConf      = "Unable to load configuration"
	ErrorDispClose = "Unable to close dispatcher"
	ErrorDispInit  = "Unable to initialize dispatcher"
	ErrorSign      = "Unable to create sign"
	ErrorSNET      = "Unable to create local SCION Network context"
)

// setupBasic loads the config from file and initializes logging.
func setupBasic() error {
	// Load and initialize config.
	if _, err := toml.DecodeFile(env.ConfigFile(), &config); err != nil {
		return err
	}
	if err := env.InitLogging(&config.Logging); err != nil {
		return err
	}
	env.LogSvcStarted(common.CS, config.General.ID)
	return nil
}

// setup initializes the config and sets the messenger.
func setup() error {
	if err := env.InitGeneral(&config.General); err != nil {
		return common.NewBasicError("Unable to initialize General config", err)
	}
	itopo.SetCurrentTopology(config.General.Topology)
	env.InitSciondClient(&config.Sciond)
	if err := config.CS.Init(config.General.ConfigDir); err != nil {
		return common.NewBasicError("Unable to initialize CS config", err)
	}
	// Load CS state.
	if err := initState(&config); err != nil {
		return common.NewBasicError("Unable to initialize CS state", err)
	}
	if err := setMessenger(&config); err != nil {
		return common.NewBasicError("Unable to set messenger", err)
	}
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
		ServiceType:        proto.ServiceType_cs,
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

// setMessenger sets the messenger and the internal messenger of the store in
// config.CS. This function may only be called once per config.
func setMessenger(config *Config) error {
	topoAddress := config.General.Topology.CS.GetById(config.General.ID)
	if topoAddress == nil {
		return common.NewBasicError("Unable to find topo address", nil)
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
	if err != nil {
		return common.NewBasicError("Unable to initialize SCION Messenger", err)
	}
	// FIXME(roosd): Hack to make Store.ChooseServer not panic.
	// Remove when https://github.com/scionproto/scion/issues/2029 is resolved.
	if err := snet.Init(config.General.Topology.ISD_AS, config.Sciond.Path, ""); err != nil {
		return common.NewBasicError("Unable to initialize snet", err)
	}
	// FIXME(roosd): We need the actual type to set the signer and verifier.
	// Remove when https://github.com/scionproto/scion/issues/2030 is resolved.
	var ok bool
	if msgr, ok = msgrI.(*messenger.Messenger); !ok {
		return common.NewBasicError("Unsupported messenger type", nil,
			"msgrI", common.TypeOf(msgrI))
	}
	msgr.AddHandler(infra.ChainRequest, config.state.Store.NewChainReqHandler(true))
	msgr.AddHandler(infra.TRCRequest, config.state.Store.NewTRCReqHandler(true))
	msgr.AddHandler(infra.Chain, config.state.Store.NewChainPushHandler())
	msgr.AddHandler(infra.TRC, config.state.Store.NewTRCPushHandler())
	msgr.UpdateSigner(config.state.GetSigner(), []infra.MessageType{infra.ChainIssueRequest})
	msgr.UpdateVerifier(config.state.GetVerifier())
	// Only core CS handles certificate reissuance requests.
	if config.General.Topology.Core {
		msgr.AddHandler(infra.ChainIssueRequest, &reiss.Handler{
			State: config.state,
			IA:    config.General.Topology.ISD_AS,
		})
	}
	return nil
}
