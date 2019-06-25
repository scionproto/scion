// Copyright 2019 ETH Zurich
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
// See the License for the specdic language governing permissions and
// limitations under the License.

package shared

import (
	"crypto/sha256"
	"hash"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket/afpacket"
	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
)

type DevInfo struct {
	Host    *net.Interface
	ContDev string
	Handle  *afpacket.TPacket
}

var (
	DevByName map[string]*DevInfo
	DevList   []*DevInfo
	HashMac   hash.Hash
	Now       = time.Now()
	TsNow32   = uint32(Now.Unix())
	NoTime    = time.Time{}
)

func UpdateNow() {
	Now = time.Now()
	TsNow32 = uint32(Now.Unix())
}

func Init(keysDirPath string) error {
	if err := initDevices(); err != nil {
		return err
	}
	if err := generateKeys(keysDirPath); err != nil {
		return err
	}
	return nil
}

func initDevices() error {
	DevByName = make(map[string]*DevInfo)

	devs, err := net.Interfaces()
	if err != nil {
		return common.NewBasicError("Unable to list interfaces", err)
	}
	for i := range devs {
		dev := devs[i]
		if strings.HasPrefix(dev.Name, "veth_") && strings.HasSuffix(dev.Name, "_host") {
			// matches braccept interface name template "veth_.*_host"
			dev := &DevInfo{
				Host:    &devs[i],
				ContDev: strings.TrimSuffix(dev.Name, "_host"),
			}
			DevList = append(DevList, dev)
			DevByName[dev.ContDev] = dev
		}
	}
	return nil
}

func generateKeys(fn string) error {
	// Load master keys
	masterKeys, err := keyconf.LoadMaster(fn)
	if err != nil {
		return err
	}
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(masterKeys.Key0, common.RawBytes("Derive OF Key"), 1000, 16, sha256.New)
	// First check for MAC creation errors.
	HashMac, err = scrypto.InitMac(hfGenKey)
	return err
}
