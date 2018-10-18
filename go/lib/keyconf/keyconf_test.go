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

package keyconf

import (
	"encoding/base64"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/common"
)

var (
	mstr0, _ = base64.StdEncoding.DecodeString("rJMIe7UcHTQxm9l13TuI3A==")
	mstr1, _ = base64.StdEncoding.DecodeString("WIn/OaISXyOCLehKNHcMKg==")

	asSigSeed, _   = base64.StdEncoding.DecodeString("6N/rjhlQjzpSeem1v2J9jmfbc8hOzlzU3M/CebbnYL8=")
	issSigSeed, _  = base64.StdEncoding.DecodeString("sp1uEH8wiMRkZR152ptC9mRCzIwIw00ASWKjD0TD21o=")
	onlineSeed, _  = base64.StdEncoding.DecodeString("dh8V4fyRp2TcEZ5qnGBF/HvYJvkPZx5kcAH9BWQJmq0=")
	offlineSeed, _ = base64.StdEncoding.DecodeString("ESJaansU6zVF1bqYwNPY9OOt8NaU7QYWIMjV1x+lAdQ=")

	asSig   = common.RawBytes(ed25519.NewKeyFromSeed(asSigSeed))
	issSig  = common.RawBytes(ed25519.NewKeyFromSeed(issSigSeed))
	online  = common.RawBytes(ed25519.NewKeyFromSeed(onlineSeed))
	offline = common.RawBytes(ed25519.NewKeyFromSeed(offlineSeed))

	decrypt, _ = base64.StdEncoding.DecodeString("fYUmQn48f0cBUUwcOpmpeZlviHXVF68XWWEMGeZvw6Y=")
)

func Test_Load(t *testing.T) {
	Convey("Load keyconf", t, func() {

		checkConf := func(c *Conf, err error, asSig, decrypt, mstr0, mstr1, issSig, online,
			offline common.RawBytes) {

			SoMsg("err", err, ShouldBeNil)
			SoMsg("mstr0", c.Master.Key0, ShouldResemble, mstr0)
			SoMsg("mstr1", c.Master.Key1, ShouldResemble, mstr1)
			SoMsg("decrypt", c.DecryptKey, ShouldResemble, decrypt)
			SoMsg("asSig", c.SignKey, ShouldResemble, asSig)
			SoMsg("issSig", c.IssSigKey, ShouldResemble, issSig)
			SoMsg("online", c.OnRootKey, ShouldResemble, online)
			SoMsg("offline", c.OffRootKey, ShouldResemble, offline)
		}

		Convey("Load all", func() {
			c, err := Load("testdata", true, true, true, true)
			checkConf(c, err, asSig, decrypt, mstr0, mstr1, issSig, online, offline)
		})
		Convey("Load master keys", func() {
			c, err := Load("testdata", false, false, false, true)
			checkConf(c, err, asSig, decrypt, mstr0, mstr1, nil, nil, nil)
		})
		Convey("Load issuer signing key", func() {
			c, err := Load("testdata", true, false, false, false)
			checkConf(c, err, asSig, decrypt, nil, nil, issSig, nil, nil)
		})
		Convey("Load online root key", func() {
			c, err := Load("testdata", false, true, false, false)
			checkConf(c, err, asSig, decrypt, nil, nil, nil, online, nil)
		})
		Convey("Load offline root key", func() {
			c, err := Load("testdata", false, false, true, false)
			checkConf(c, err, asSig, decrypt, nil, nil, nil, nil, offline)
		})
	})
}
