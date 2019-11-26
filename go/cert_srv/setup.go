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
	"github.com/scionproto/scion/go/cert_srv/internal/reiss"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

const (
	ErrConf      common.ErrMsg = "Unable to load configuration"
	ErrDispClose common.ErrMsg = "Unable to close dispatcher"
	ErrDispInit  common.ErrMsg = "Unable to initialize dispatcher"
	ErrSign      common.ErrMsg = "Unable to create sign"
	ErrSNET      common.ErrMsg = "Unable to create local SCION Network context"
)

// setupBasic loads the config from file and initializes logging.
func setupBasic() error {
	// Load and initialize config.
	if _, err := toml.DecodeFile(env.ConfigFile(), &cfg); err != nil {
		return err
	}
	cfg.InitDefaults()
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
	}
	prom.ExportElementID(cfg.General.ID)
	return env.LogAppStarted(common.CS, cfg.General.ID)
}

// setup initializes the config and sets the messenger.
func setup() error {
	if err := cfg.Validate(); err != nil {
		return common.NewBasicError("Unable to validate config", err)
	}
	itopo.Init(cfg.General.ID, proto.ServiceType_cs, itopo.Callbacks{})
	topo, err := itopo.LoadFromFile(cfg.General.Topology)
	if err != nil {
		return common.NewBasicError("Unable to load topology", err)
	}
	if err := initTopo(topo); err != nil {
		return err
	}
	router, err := infraenv.NewRouter(topo.IA(), cfg.Sciond)
	if err != nil {
		return common.NewBasicError("Unable to initialize path router", err)
	}
	// Load CS state.
	if err := initState(&cfg, router); err != nil {
		return common.NewBasicError("Unable to initialize CS state", err)
	}
	if err := setMessenger(&cfg, router); err != nil {
		return common.NewBasicError("Unable to set messenger", err)
	}
	return nil
}

// reload reloads the topology and CS config.
func reload() error {
	// FIXME(roosd): KeyConf reloading is not yet supported.
	// https://github.com/scionproto/scion/issues/2077
	var newConf config.Config
	// Load new config to get the CS parameters.
	if _, err := toml.DecodeFile(env.ConfigFile(), &newConf); err != nil {
		return err
	}
	newConf.InitDefaults()
	if err := newConf.Validate(); err != nil {
		return common.NewBasicError("Unable to validate new config", err)
	}
	cfg.CS = newConf.CS
	// Restart the periodic reissue task to respect the fresh parameters.
	stopReissRunner()
	startReissRunner()
	return nil
}

// initState sets the state.
func initState(cfg *config.Config, router snet.Router) error {
	topo := itopo.Get()
	var err error
	if trustDB, err = cfg.TrustDB.New(); err != nil {
		return common.NewBasicError("Unable to initialize trustDB", err)
	}
	trustDB = trustdb.WithMetrics(string(cfg.TrustDB.Backend()), trustDB)
	trustConf := trust.Config{
		MustHaveLocalChain: true,
		ServiceType:        proto.ServiceType_cs,
		Router:             router,
		TopoProvider:       itopo.Provider(),
	}
	trustStore := trust.NewStore(trustDB, topo.IA(), trustConf, log.Root())
	err = trustStore.LoadAuthoritativeCrypto(filepath.Join(cfg.General.ConfigDir, "certs"))
	if err != nil {
		return common.NewBasicError("Unable to load local crypto", err)
	}
	state, err = config.LoadState(cfg.General.ConfigDir, topo.Core(), trustDB, trustStore)
	if err != nil {
		return common.NewBasicError("Unable to load CS state", err)
	}
	if err = setDefaultSignerVerifier(state, topo.IA()); err != nil {
		return common.NewBasicError("Unable to set default signer and verifier", err)
	}
	return nil
}

// setDefaultSignerVerifier sets the signer and verifier. The newest certificate chain version
// in the store is used.
func setDefaultSignerVerifier(c *config.State, pubIA addr.IA) error {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	meta, err := trust.CreateSignMeta(ctx, pubIA, c.TrustDB)
	if err != nil {
		return err
	}
	signer, err := trust.NewBasicSigner(c.GetSigningKey(), meta)
	if err != nil {
		return err
	}
	c.SetSigner(signer)
	c.SetVerifier(c.Store.NewVerifier())
	return nil
}

// setMessenger sets the messenger and the internal messenger of the store in
// cfg.CS. This function may only be called once per config.
func setMessenger(cfg *config.Config, router snet.Router) error {
	topo := itopo.Get()
	if !topo.Exists(addr.SvcCS, cfg.General.ID) {
		return serrors.New("unable to find topo address")
	}
	nc := infraenv.NetworkConfig{
		IA:                    topo.IA(),
		Public:                topo.PublicAddress(addr.SvcCS, cfg.General.ID),
		SVC:                   addr.SvcCS,
		ReconnectToDispatcher: cfg.General.ReconnectToDispatcher,
		QUIC: infraenv.QUIC{
			Address:  cfg.QUIC.Address,
			CertFile: cfg.QUIC.CertFile,
			KeyFile:  cfg.QUIC.KeyFile,
		},
		SVCResolutionFraction: cfg.QUIC.ResolutionFraction,
		TrustStore:            state.Store,
		Router:                router,
		SVCRouter:             messenger.NewSVCRouter(itopo.Provider()),
	}
	var err error
	msgr, err = nc.Messenger()
	if err != nil {
		return common.NewBasicError("Unable to initialize SCION Messenger", err)
	}
	msgr.AddHandler(infra.ChainRequest, state.Store.NewChainReqHandler(true))
	msgr.AddHandler(infra.TRCRequest, state.Store.NewTRCReqHandler(true))
	msgr.AddHandler(infra.Chain, state.Store.NewChainPushHandler())
	msgr.AddHandler(infra.TRC, state.Store.NewTRCPushHandler())
	msgr.UpdateSigner(state.GetSigner(), []infra.MessageType{infra.ChainIssueRequest})
	msgr.UpdateVerifier(state.GetVerifier())
	// Only core CS handles certificate reissuance requests.
	if topo.Core() {
		msgr.AddHandler(infra.ChainIssueRequest, &reiss.Handler{
			State: state,
			IA:    topo.IA(),
		})
	}
	return nil
}

func initTopo(topo itopo.Topology) error {
	if _, _, err := itopo.SetStatic(topo, false); err != nil {
		return common.NewBasicError("Unable to set initial static topology", err)
	}
	// Set environment to listen for signals.
	infraenv.InitInfraEnvironmentFunc(cfg.General.Topology, func() {
		if err := reload(); err != nil {
			log.Error("Unable to reload", "err", err)
		}
	})
	return nil
}
