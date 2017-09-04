// Copyright 2017 ETH Zurich
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

// +build infrarunning

package sciond

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/util"
)

var (
	token = "\x10\x51\x50\x03\x04\x01\x57\x0f" +
		"\x9f\x13\xf7\x08\x05\x0b\x10\x31\x0d\x02\x01\x11\x19\xa7\x33\x09" +
		"\x01\x02\x01\x33\x15\x01\x02\x01\xff\xd7\x83\xed\x12\x4b\x38\x57" +
		"\x0d\x03\xd1\xc8\x5c\x2e\xf7\x61\x1e\x41\x09\x4a\xf9\xbe\x45\x2c" +
		"\x60\xca\x64\x79\xa2\xab\xf7\xfe\x26\x22\x51\x28\x01\x01\x01\x01" +
		"\x31\x49\x02\x01\x01\x01\x31\x51\x02\x01\x01\x01\x31\x59\x02\x01" +
		"\x01\x01\x31\x61\x02\x01\x01\x01\x31\x69\x02\x01\x01\x01\x31\x71" +
		"\x02\x01\x00\x00\x31\x79\x02\x01\x01\x01\x31\x81\x02\x01\x00\x00" +
		"\x31\x89\x02\x01\x01\x01\x31\x91\x02\x01\xff\x2e\xc4\xd7\x05\xa8" +
		"\xfb\x47\x73\x2f\x25\xb9\xfc\x93\x2c\x96\x5f\xcf\x0b\xf5\x42\xd4" +
		"\xed\xd6\x0a\x18\x7f\x66\x39\x4e\xcd\x0d\x72\x4e\x3d\x81\x83\x7f" +
		"\xd8\xb3\xb6\x1f\x15\x9c\xc2\x77\x74\x47\x4e\x0e\x0c\xa2\x74\xae" +
		"\x83\xd7\x6c\x68\xb4\x97\x33\x5e\x35\xc4\x7a\x82\xdc\x07\x1d\x06" +
		"\x94\x14\x06\x07\xe0\xad\xd9\x0f\xf6\x26\xb0\x38\x79\xce\xcb\x4f" +
		"\x6d\xcd\x78\x76\x4c\xdd\x5e\x6a\x42\x39\xb4\x84\x3b\x76\x4d\x5f" +
		"\x4c\xe8\x2a\x1a\xe3\x8c\x46\x10\x2f\xd0\x8a\xcc\xe6\xd9\x14\xf0" +
		"\x10\x82\xda\x12\xb8\xf9\x0d\x73\x3b\xa9\xc0\x64\x28\xbb\x46\xfd" +
		"\x33\xa4\x16\x6e\x77\x22\xe4\x26\xda\x43\xe7\x37\x82\xa9\xed\xe8" +
		"\xe2\xe1\xac\x4a\xfb\xfb\xbd\x70\xb6\x04\x91\xd9\xe8\x44\x9c\xff" +
		"\x95\xea\xd3\xf8\x8c\xf6\x34\x2e\x0b\x21\x2c\x69\x87\xd1\xce\x29" +
		"\x37\x81\xe8\xb7\xe8\x28\xd8\x8e\xc5\x66\x65\xab\x53\x81\xf4\x6e" +
		"\x4e\x85\x2f\x5e\xd0\x88\x6e\x24\x55\xf6\xbf\xa0\xd8\xbf\x04\x5d" +
		"\x41\x9e\x0f\xad\xfc\x55\x02\x1a\x9c\x84\xfa\xf7\xd6\xd8\x01\x8f" +
		"\x00\x44\xf3\x06\x6d\x40\x68\x0c\x09\xfb\xd1\xde\x44\xf5\xd7\xd1" +
		"\xca\x1c\x70\x5e\x7d\x44\x96\xcb\x39\xfc\xa7\xd2\xfd\xc3\xc3\x1e" +
		"\x5b\xc0\x1b\x8e\x3e\x66\xb7\xb4\x3a\x1b\x62\x07\x43\xc9\xc2\xc4" +
		"\x44\x22\x6f\x91\x60\x9a\x86\x44\xb2\xd8\x94\xb2\x82\x3f\xb2\x72" +
		"\x76\xa5\xf0\xb8\x3f\x76\x68\x1c\x80\xef\x52\xb7\xd7\x13\xa4\xcb" +
		"\x79\xff\x36\x3e\xca\x22\xd8\x69\x90\xc3\x12\xee\x08\xbc\x06\xde" +
		"\x3d\xee\xd7\x51\x02\x5e\xe8\x0f\x0e\x8c\x76\xe1\x4f\x33\x5f\x33" +
		"\xc5\x3b\xaf\x51\x59\xce\xc9\x5c\x7f\xcc\x54\xfa\xa8\xc6\xb2\x72" +
		"\x72\xce\x2c\xc5\x84\xf0\x90\xae\xea\x49\x5f\x04\xc3\xbb\x9c\xc8" +
		"\x88\x70\x27\x3a\x27\xef\xf7\x28\x51\xb3\x24\x04\x00\x00\x00\x00"
)

func TestRevNotification(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	Convey("Old revocations should return correct status code", t, func() {
		asStruct, err := util.LoadASList("../../../gen/as_list.yml")
		SoMsg("AS selection error", err, ShouldBeNil)

		asList := append(asStruct.NonCore, asStruct.Core...)
		SoMsg("AS selection len", len(asList), ShouldBeGreaterThan, 0)
		localIA := asList[rand.Intn(len(asList))]

		conn, err := Connect(fmt.Sprintf("/run/shm/sciond/sd%v.sock", localIA))
		SoMsg("Connect error", err, ShouldBeNil)

		reply, err := conn.RevNotificationFromRaw([]byte(token))
		SoMsg("RevNotification error", err, ShouldBeNil)
		SoMsg("Status", reply.Status, ShouldEqual, RevTooOld)
	})
}
