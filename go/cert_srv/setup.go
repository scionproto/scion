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

// setup loads and sets the newest configuration. If needed, the snet/dispatcher are initialized.
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
	// Close dispatcher if the addresses are changed
	if oldConf != nil && (!oldConf.PublicAddr.EqAddr(newConf.PublicAddr) ||
		!oldConf.BindAddr.EqAddr(newConf.BindAddr)) {
		if err := disp.Close(); err != nil {
			return common.NewBasicError(ErrorDispClose, err)
		}
	}
	// Set the new configuration.
	conf.Set(newConf)
	// Initialize snet with retries if not already initialized
	if oldConf == nil {
		if err = initSNET(newConf.PublicAddr.IA, initAttempts, initInterval); err != nil {
			return common.NewBasicError(ErrorSNET, err)
		}
	}
	// Create new dispatcher if it does not exist or is closed
	if oldConf == nil || disp.closed {
		if disp, err = NewDispatcher(newConf.PublicAddr, newConf.BindAddr); err != nil {
			return common.NewBasicError(ErrorDispInit, err)
		}
		defer func() { go disp.Run() }()
	}
	return nil
}

// loadConf loads the newest configuration.
func loadConf(oldConf *conf.Conf) (*conf.Conf, error) {
	if oldConf != nil {
		return conf.ReloadConf(oldConf)
	}
	return conf.Load(*id, *confDir, *cacheDir, *stateDir)
}

// setDefaultSignerVerifier sets the signer and verifier. The newest certificate chain version is
// used.
func setDefaultSignerVerifier(c *conf.Conf) error {
	sign, err := CreateSign(c.PublicAddr.IA, c.Store)
	if err != nil {
		return err
	}
	c.SetSigner(ctrl.NewBasicSigner(sign, c.GetSigningKey()))
	c.SetVerifier(&SigVerifier{&ctrl.BasicSigVerifier{}})
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
