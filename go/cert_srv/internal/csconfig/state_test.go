// Copyright 2018 Anapaya Systems
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

package csconfig

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/scrypto"
)

var (
	master0 = loadKey("testdata/keys/master0.key", trust.RawKey)
	master1 = loadKey("testdata/keys/master1.key", trust.RawKey)
	decrypt = loadKey("testdata/keys/as-decrypt.key", scrypto.Curve25519xSalsa20Poly1305)
	asSig   = loadKey("testdata/keys/as-sig.seed", scrypto.Ed25519)
	issSig  = loadKey("testdata/keys/core-sig.seed", scrypto.Ed25519)
	online  = loadKey("testdata/keys/online-root.seed", scrypto.Ed25519)
)

func TestLoadState(t *testing.T) {
	Convey("Load core state", t, func() {
		state, err := LoadState("testdata", true)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("Master0", state.MasterKeys.Key0, ShouldResemble, master0)
		SoMsg("Master1", state.MasterKeys.Key1, ShouldResemble, master1)
		SoMsg("Decrypt", state.keyConf.DecryptKey, ShouldResemble, decrypt)
		SoMsg("AS-Sign", state.keyConf.SignKey, ShouldResemble, asSig)
		SoMsg("Issuer-Sign", state.keyConf.IssSigKey, ShouldResemble, issSig)
		SoMsg("Online", state.keyConf.OnRootKey, ShouldResemble, online)
		SoMsg("Offline", state.keyConf.OffRootKey, ShouldBeZeroValue)
	})

	Convey("Load non-core state", t, func() {
		state, err := LoadState("testdata", false)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("Master0", state.MasterKeys.Key0, ShouldResemble, master0)
		SoMsg("Master1", state.MasterKeys.Key1, ShouldResemble, master1)
		SoMsg("Decrypt", state.keyConf.DecryptKey, ShouldResemble, decrypt)
		SoMsg("AS-Sign", state.keyConf.SignKey, ShouldResemble, asSig)
		SoMsg("Issuer-Sign", state.keyConf.IssSigKey, ShouldBeZeroValue)
		SoMsg("Online", state.keyConf.OnRootKey, ShouldBeZeroValue)
		SoMsg("Offline", state.keyConf.OffRootKey, ShouldBeZeroValue)
	})
}

func loadKey(file string, algo string) common.RawBytes {
	key, err := trust.LoadKey(file, algo)
	if err != nil {
		panic(err)
	}
	return key
}
