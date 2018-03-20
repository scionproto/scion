// Note:
//
// This temporary file is included as a proof of concept. It will not be pushed
// to the upstream repository.

package loader

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestExample(t *testing.T) {
	Convey("Compile and run Go program", t, func() {
		dir, f := MustTempDir("", "example")
		defer f()

		b := Binary{
			Target: "github.com/scionproto/scion/go/tmp",
			Dir:    dir,
			Prefix: "mainbin",
		}
		err := b.Build()
		SoMsg("err", err, ShouldBeNil)

		output, err := b.Cmd().CombinedOutput()
		SoMsg("err", err, ShouldBeNil)
		SoMsg("output", string(output), ShouldEqual, dir)
	})
}
