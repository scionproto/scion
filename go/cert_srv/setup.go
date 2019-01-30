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
	"context"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/cert_srv/internal/metrics"
	"github.com/scionproto/scion/go/cert_srv/internal/reiss"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
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
	if _, err := toml.DecodeFile(env.ConfigFile(), &cfg); err != nil {
		return err
	}
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
	}
	metrics.Init(cfg.General.ID)
	return env.LogAppStarted(common.CS, cfg.General.ID)
}

// setup initializes the config and sets the messenger.
func setup() error {
	if err := env.InitGeneral(&cfg.General); err != nil {
		return common.NewBasicError("Unable to initialize General config", err)
	}
	itopo.Init(cfg.General.ID, proto.ServiceType_cs, itopo.Callbacks{})
	if _, _, err := itopo.SetStatic(cfg.General.Topology, false); err != nil {
		return common.NewBasicError("Unable to set initial static topology", err)
	}
	env.InitSciondClient(&cfg.Sciond)
	if err := cfg.Init(cfg.General.ConfigDir); err != nil {
		return common.NewBasicError("Unable to initialize CS config", err)
	}
	// Load CS state.
	if err := initState(&cfg); err != nil {
		return common.NewBasicError("Unable to initialize CS state", err)
	}
	if err := setMessenger(&cfg); err != nil {
		return common.NewBasicError("Unable to set messenger", err)
	}
	return nil
}

// initState sets the state.
func initState(cfg *config.Config) error {
	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		return common.NewBasicError("Unable to initialize trustDB", err)
	}
	trustDB = trustdb.WithMetrics("std", trustDB)
	trustConf := &trust.Config{
		MustHaveLocalChain: true,
		ServiceType:        proto.ServiceType_cs,
	}
	trustStore, err := trust.NewStore(trustDB, cfg.General.Topology.ISD_AS,
		trustConf, log.Root())
	if err != nil {
		return common.NewBasicError("Unable to initialize trust store", err)
	}
	state, err = config.LoadState(cfg.General.ConfigDir, cfg.General.Topology.Core,
		trustDB, trustStore)
	if err != nil {
		return common.NewBasicError("Unable to load CS state", err)
	}
	err = state.Store.LoadAuthoritativeTRC(filepath.Join(cfg.General.ConfigDir, "certs"))
	if err != nil {
		return common.NewBasicError("Unable to load local TRC", err)
	}
	err = state.Store.LoadAuthoritativeChain(
		filepath.Join(cfg.General.ConfigDir, "certs"))
	if err != nil {
		return common.NewBasicError("Unable to load local Chain", err)
	}
	if err = setDefaultSignerVerifier(state, cfg.General.Topology.ISD_AS); err != nil {
		return common.NewBasicError("Unable to set default signer and verifier", err)
	}
	return nil
}

// setDefaultSignerVerifier sets the signer and verifier. The newest certificate chain version
// in the store is used.
func setDefaultSignerVerifier(c *config.State, pubIA addr.IA) error {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	sign, err := trust.CreateSign(ctx, pubIA, c.TrustDB)
	if err != nil {
		return err
	}
	c.SetSigner(trust.NewBasicSigner(sign, c.GetSigningKey()))
	c.SetVerifier(trust.NewBasicSigVerifier(c.Store))
	return nil
}

// setMessenger sets the messenger and the internal messenger of the store in
// cfg.CS. This function may only be called once per config.
func setMessenger(cfg *config.Config) error {
	topoAddress := cfg.General.Topology.CS.GetById(cfg.General.ID)
	if topoAddress == nil {
		return common.NewBasicError("Unable to find topo address", nil)
	}
	var err error
	msgr, err = infraenv.InitMessengerWithSciond(
		cfg.General.Topology.ISD_AS,
		env.GetPublicSnetAddress(cfg.General.Topology.ISD_AS, topoAddress),
		env.GetBindSnetAddress(cfg.General.Topology.ISD_AS, topoAddress),
		addr.SvcCS,
		cfg.General.ReconnectToDispatcher,
		state.Store,
		cfg.Sciond,
	)
	if err != nil {
		return common.NewBasicError("Unable to initialize SCION Messenger", err)
	}
	// FIXME(roosd): Hack to make Store.ChooseServer not panic.
	// Remove when https://github.com/scionproto/scion/issues/2029 is resolved.
	if err := snet.Init(cfg.General.Topology.ISD_AS, cfg.Sciond.Path, ""); err != nil {
		return common.NewBasicError("Unable to initialize snet", err)
	}
	msgr.AddHandler(infra.ChainRequest, state.Store.NewChainReqHandler(true))
	msgr.AddHandler(infra.TRCRequest, state.Store.NewTRCReqHandler(true))
	msgr.AddHandler(infra.Chain, state.Store.NewChainPushHandler())
	msgr.AddHandler(infra.TRC, state.Store.NewTRCPushHandler())
	msgr.UpdateSigner(state.GetSigner(), []infra.MessageType{infra.ChainIssueRequest})
	msgr.UpdateVerifier(state.GetVerifier())
	// Only core CS handles certificate reissuance requests.
	if cfg.General.Topology.Core {
		msgr.AddHandler(infra.ChainIssueRequest, &reiss.Handler{
			State: state,
			IA:    cfg.General.Topology.ISD_AS,
		})
	}
	return nil
}
