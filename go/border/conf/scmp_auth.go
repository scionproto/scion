// Copyright 2016 ETH Zurich
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

// This holds all of the global router state regarding SCMPAuth, for access by the
// router's various packages.
package conf

import (
	"crypto/cipher"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

// SCMPAuthConf is the main config structure.
type SCMPAuthConf struct {
	// SCMPAuthBlock is the DRKey generation block cipher instance
	AESBlock cipher.Block
	// missingDRKeyQsize
	MissingDRKeyQsize int
	// time between retries
	DRKeyRequestRetryTime int64
	// time until request is dropped
	DRKeyRequestTimeout int64
	//
	NumberOfQueues int
	//
	MaxQueueSize int
}

// C is a pointer to the current configuration.
var SCMPAuth *SCMPAuthConf

// LoadSCMPAuth sets up the SCMPAuth configuration, loading it from the supplied config directory.
// config.Load has to be called first.
func LoadSCMPAuth() *common.Error {
	var err *common.Error

	if C == nil {
		return common.NewError("Conf is has not been initialized yet")
	}

	// Declare a new SCMPAuthConf instance.
	scmpAuthConf := &SCMPAuthConf{}

	// Derive the SCMPAuth master secret.
	scmpAuthGenKey := pbkdf2.Key(C.ASConf.MasterASKey, []byte("Derive SCMP Key"), 1000, 16, sha1.New)
	if scmpAuthConf.AESBlock, err = util.InitAES(scmpAuthGenKey); err != nil {
		return err
	}

	// Magic numbers. TODO(roosd): replace with config file, which can be loaded.
	scmpAuthConf.MissingDRKeyQsize = 1024
	scmpAuthConf.DRKeyRequestTimeout = 1000000000
	scmpAuthConf.MaxQueueSize = 1000
	scmpAuthConf.NumberOfQueues = 10

	// Save config
	SCMPAuth = scmpAuthConf
	return nil
}
