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
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/sciond"
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

type TestConfig struct {
	CS *Conf
}

func TestLoadConf(t *testing.T) {
	Convey("Load Conf", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeFile("testdata/csconfig.toml", &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("leafTime", cfg.CS.LeafReissueTime.Duration, ShouldEqual, 7*time.Hour)
		SoMsg("issuerTime", cfg.CS.IssuerReissueTime.Duration, ShouldEqual, 2*24*time.Hour)
		SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, 12*time.Second)
		SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, 6*time.Second)
		SoMsg("sciondPath", cfg.CS.SciondPath, ShouldEqual, "/run/shm/sciond/sd1-ff00_0_110.sock")
		SoMsg("sciondTimeout", cfg.CS.SciondTimeout.Duration, ShouldEqual, 20*time.Second)
		SoMsg("sciondRetryInterval", cfg.CS.SciondRetryInterval.Duration,
			ShouldEqual, 3*time.Second)
	})

	Convey("Load Default", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeReader(strings.NewReader("[cs]"), &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("leafTime", cfg.CS.LeafReissueTime.Duration, ShouldBeZeroValue)
		SoMsg("issuerTime", cfg.CS.IssuerReissueTime.Duration, ShouldBeZeroValue)
		SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldBeZeroValue)
		SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldBeZeroValue)
		SoMsg("sciondPath", cfg.CS.SciondPath, ShouldBeZeroValue)
		SoMsg("sciondTimeout", cfg.CS.SciondTimeout.Duration, ShouldBeZeroValue)
		SoMsg("sciondRetryInterval", cfg.CS.SciondRetryInterval.Duration, ShouldBeZeroValue)
	})
}

func TestConfig_Init(t *testing.T) {
	Convey("Load Conf", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeFile("testdata/csconfig.toml", &cfg)
		SoMsg("err", err, ShouldBeNil)

		Convey("Init does not override values", func() {
			err := cfg.CS.Init("testdata", false)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("leafTime", cfg.CS.LeafReissueTime.Duration, ShouldEqual, 7*time.Hour)
			SoMsg("issuerTime", cfg.CS.IssuerReissueTime.Duration, ShouldEqual, 48*time.Hour)
			SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, 12*time.Second)
			SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, 6*time.Second)
			SoMsg("sciondPath", cfg.CS.SciondPath, ShouldEqual,
				"/run/shm/sciond/sd1-ff00_0_110.sock")
			SoMsg("sciondTimeout", cfg.CS.SciondTimeout.Duration, ShouldEqual, 20*time.Second)
			SoMsg("sciondRetryInterval", cfg.CS.SciondRetryInterval.Duration,
				ShouldEqual, 3*time.Second)
		})

		Convey("Init loads keys correctly for core", func() {
			err := cfg.CS.Init("testdata", true)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("Master0", cfg.CS.MasterKeys.Key0, ShouldResemble, master0)
			SoMsg("Master1", cfg.CS.MasterKeys.Key1, ShouldResemble, master1)
			SoMsg("Decrypt", cfg.CS.keyConf.DecryptKey, ShouldResemble, decrypt)
			SoMsg("AS-Sign", cfg.CS.keyConf.SignKey, ShouldResemble, asSig)
			SoMsg("Issuer-Sign", cfg.CS.keyConf.IssSigKey, ShouldResemble, issSig)
			SoMsg("Online", cfg.CS.keyConf.OnRootKey, ShouldResemble, online)
			SoMsg("Offline", cfg.CS.keyConf.OffRootKey, ShouldBeZeroValue)
		})

		Convey("Init loads keys correctly for non-core", func() {
			err := cfg.CS.Init("testdata", false)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("Master0", cfg.CS.MasterKeys.Key0, ShouldResemble, master0)
			SoMsg("Master1", cfg.CS.MasterKeys.Key1, ShouldResemble, master1)
			SoMsg("Decrypt", cfg.CS.keyConf.DecryptKey, ShouldResemble, decrypt)
			SoMsg("AS-Sign", cfg.CS.keyConf.SignKey, ShouldResemble, asSig)
			SoMsg("Issuer-Sign", cfg.CS.keyConf.IssSigKey, ShouldBeZeroValue)
			SoMsg("Online", cfg.CS.keyConf.OnRootKey, ShouldBeZeroValue)
			SoMsg("Offline", cfg.CS.keyConf.OffRootKey, ShouldBeZeroValue)
		})
	})

	Convey("Load Default", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeReader(strings.NewReader("[cs]"), &cfg)
		SoMsg("err", err, ShouldBeNil)

		Convey("Init loads default values", func() {
			err := cfg.CS.Init("testdata", false)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("leafTime", cfg.CS.LeafReissueTime.Duration, ShouldEqual, 6*time.Hour)
			SoMsg("issuerTime", cfg.CS.IssuerReissueTime.Duration, ShouldEqual, IssuerReissTime)
			SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, ReissReqRate)
			SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, ReissueReqTimeout)
			SoMsg("sciondPath", cfg.CS.SciondPath, ShouldEqual, sciond.DefaultSCIONDPath)
			SoMsg("sciondTimeout", cfg.CS.SciondTimeout.Duration, ShouldEqual, SciondTimeout)
			SoMsg("sciondRetryInterval", cfg.CS.SciondRetryInterval.Duration,
				ShouldEqual, SciondRetryInterval)
		})
	})
}

func loadKey(file string, algo string) common.RawBytes {
	key, err := trust.LoadKey(file, algo)
	if err != nil {
		panic(err)
	}
	return key
}
