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

	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
)

var (
	mstr0, _  = keyconf.LoadKey("testdata/keys/master0.key", keyconf.RawKey)
	mstr1, _  = keyconf.LoadKey("testdata/keys/master1.key", keyconf.RawKey)
	dcrpt, _  = keyconf.LoadKey("testdata/keys/as-decrypt.key", scrypto.Curve25519xSalsa20Poly1305)
	asSig, _  = keyconf.LoadKey("testdata/keys/as-sig.seed", scrypto.Ed25519)
	issSig, _ = keyconf.LoadKey("testdata/keys/core-sig.seed", scrypto.Ed25519)
	online, _ = keyconf.LoadKey("testdata/keys/online-root.seed", scrypto.Ed25519)
)

func TestLoadState(t *testing.T) {
	Convey("Load core state", t, func() {
		state, err := LoadState("testdata", true, nil, nil)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("Master0", state.keyConf.Master.Key0, ShouldResemble, mstr0)
		SoMsg("Master1", state.keyConf.Master.Key1, ShouldResemble, mstr1)
		SoMsg("Decrypt", state.keyConf.DecryptKey, ShouldResemble, dcrpt)
		SoMsg("AS-Sign", state.keyConf.SignKey, ShouldResemble, asSig)
		SoMsg("Issuer-Sign", state.keyConf.IssSigKey, ShouldResemble, issSig)
		SoMsg("Online", state.keyConf.OnRootKey, ShouldResemble, online)
		SoMsg("Offline", state.keyConf.OffRootKey, ShouldBeZeroValue)
	})

	Convey("Load non-core state", t, func() {
		state, err := LoadState("testdata", false, nil, nil)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("Master0", state.keyConf.Master.Key0, ShouldResemble, mstr0)
		SoMsg("Master1", state.keyConf.Master.Key1, ShouldResemble, mstr1)
		SoMsg("Decrypt", state.keyConf.DecryptKey, ShouldResemble, dcrpt)
		SoMsg("AS-Sign", state.keyConf.SignKey, ShouldResemble, asSig)
		SoMsg("Issuer-Sign", state.keyConf.IssSigKey, ShouldBeZeroValue)
		SoMsg("Online", state.keyConf.OnRootKey, ShouldBeZeroValue)
		SoMsg("Offline", state.keyConf.OffRootKey, ShouldBeZeroValue)
	})
}
