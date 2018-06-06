package scrypto

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNonce(t *testing.T) {
	Convey("Nonce should return a random byte sequence", t, func() {
		rawNonce, err := Nonce(32)
		SoMsg("err", err, ShouldBeNil)
		newNonce, err := Nonce(32)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("rawNonce", rawNonce, ShouldNotResemble, newNonce)
	})

	Convey("Nonce length is equal to input", t, func() {
		rawNonce, err := Nonce(24)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("rawNonce", len(rawNonce), ShouldResemble, 24)
		rawNonce, err = Nonce(32)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("rawNonce", len(rawNonce), ShouldResemble, 32)
	})

	Convey("Nonce should throw an error for an invalid length", t, func() {
		_, err := Nonce(0)
		SoMsg("err", err, ShouldNotBeNil)
		_, err = Nonce(-1)
		SoMsg("err", err, ShouldNotBeNil)
	})
}
