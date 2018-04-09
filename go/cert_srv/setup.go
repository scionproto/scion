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
	"path/filepath"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/cert_srv/csctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/trust"
)

const (
	ErrorCtx       = "Unable to load context"
	ErrorDispClose = "Unable to close dispatcher"
	ErrorDispInit  = "Unable to initialize dispatcher"
	ErrorSign      = "Unable to create sign"
	ErrorSNET      = "Unable to create local SCION Network context"
)

// setup loads and sets the newest context. If needed, the snet/dispatcher are initialized.
func setup() error {
	oldCtx := csctx.Get()
	if oldCtx != nil {
		defer oldCtx.TrustDB.Close()
		oldCtx.Conf.Customers.Close()
	}
	newCtx, err := createCtx()
	if err != nil {
		return common.NewBasicError(ErrorCtx, err)
	}
	// Set signer and verifier
	sign, err := CreateSign(newCtx.Conf.PublicAddr.IA, newCtx.Store)
	if err != nil {
		return common.NewBasicError(ErrorSign, err)
	}
	newCtx.Conf.SetSigner(ctrl.NewBasicSigner(sign, newCtx.Conf.GetSigningKey()))
	newCtx.Conf.SetVerifier(&SigVerifier{&ctrl.BasicSigVerifier{}})
	// Initialize snet with retries if not already initialized
	if oldCtx == nil {
		if err = initSNET(newCtx.Conf.PublicAddr.IA, initAttempts, initInterval); err != nil {
			return common.NewBasicError(ErrorSNET, err)
		}
	}
	// Close dispatcher if the addresses are changed
	if oldCtx != nil && (!oldCtx.Conf.PublicAddr.EqAddr(newCtx.Conf.PublicAddr) ||
		!oldCtx.Conf.BindAddr.EqAddr(newCtx.Conf.BindAddr)) {
		if err := disp.Close(); err != nil {
			return common.NewBasicError(ErrorDispClose, err)
		}
	}
	// Create new dispatcher if it does not exist or is closed
	if oldCtx == nil || disp.closed {
		if disp, err = NewDispatcher(newCtx.Conf.PublicAddr, newCtx.Conf.BindAddr); err != nil {
			return common.NewBasicError(ErrorDispInit, err)
		}
		defer func() { go disp.Run() }()
	}
	csctx.Set(newCtx)
	return nil
}

// createCtx creates the newest context.
func createCtx() (*csctx.Ctx, error) {
	c, err := conf.Load(*id, *confDir, *cacheDir, *stateDir)
	if err != nil {
		return nil, err
	}
	ctx := &csctx.Ctx{Conf: c}
	ctx.Store, err = trust.NewStore(filepath.Join(*confDir, "certs"), *cacheDir, *id)
	if err != nil {
		return nil, common.NewBasicError("Unable to load TrustStore", err)
	}
	ctx.TrustDB, err = trustdb.New(filepath.Join(*stateDir, trustdb.Path))
	if err != nil {
		return nil, common.NewBasicError("Unable to load trust DB", err)
	}
	return ctx, nil
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
