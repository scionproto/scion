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

package scrypto_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/scrypto"
)

func TestNonce(t *testing.T) {
	Convey("Nonce should return a random byte sequence", t, func() {
		rawNonce, err := scrypto.Nonce(32)
		SoMsg("err", err, ShouldBeNil)
		newNonce, err := scrypto.Nonce(32)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("rawNonce", rawNonce, ShouldNotResemble, newNonce)
	})

	Convey("Nonce length is equal to input", t, func() {
		rawNonce, err := scrypto.Nonce(24)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("rawNonce", len(rawNonce), ShouldResemble, 24)
		rawNonce, err = scrypto.Nonce(32)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("rawNonce", len(rawNonce), ShouldResemble, 32)
	})

	Convey("Nonce should throw an error for an invalid length", t, func() {
		_, err := scrypto.Nonce(0)
		SoMsg("err", err, ShouldNotBeNil)
		_, err = scrypto.Nonce(-1)
		SoMsg("err", err, ShouldNotBeNil)
	})
}
