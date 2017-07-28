package util

import (
	"encoding/binary"
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/common"
)

func TestChecksum(t *testing.T) {
	tests := []struct {
		Input  common.RawBytes
		Output [2]byte
	}{
		{common.RawBytes{0x00, 0x01}, [2]byte{0xff, 0xfe}},
		{common.RawBytes{0x34, 0x88, 0x19, 0x55}, [2]byte{0xb2, 0x22}},
		{common.RawBytes{0x17, 0x00}, [2]byte{0xe8, 0xff}},
		{common.RawBytes{0x11, 0x11}, [2]byte{0xee, 0xee}},
		{common.RawBytes{0xef}, [2]byte{0x10, 0xff}},
	}

	Convey("Test checksum", t, func() {
		for _, test := range tests {
			checksum := make([]byte, 2)
			binary.BigEndian.PutUint16(checksum, Checksum(test.Input))
			Convey(fmt.Sprintf("Input %v", test.Input), func() {
				So(checksum[0], ShouldEqual, test.Output[0])
				So(checksum[1], ShouldEqual, test.Output[1])
			})
		}
	})
}
