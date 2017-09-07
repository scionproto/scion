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

	"github.com/netsec-ethz/scion/go/lib/util"
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
		SoMsg("Result", reply.Result, ShouldEqual, RevInvalid)
	})
}
