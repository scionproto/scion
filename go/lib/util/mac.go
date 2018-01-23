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

package util

import (
	"crypto/aes"
	"hash"

	"github.com/dchest/cmac"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	ErrorCipherFailure = "Unable to initalize AES cipher"
	ErrorMacFailure    = "Unable to initalize Mac"
)

func InitMac(key common.RawBytes) (hash.Hash, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, common.NewBasicError(ErrorCipherFailure, err)
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, common.NewBasicError(ErrorMacFailure, err)
	}
	return mac, nil
}

func Mac(mac hash.Hash, msg common.RawBytes) (common.RawBytes, error) {
	mac.Write(msg)
	tmp := make([]byte, 0, mac.Size())
	tag := mac.Sum(tmp)
	mac.Reset()
	return tag, nil
}
