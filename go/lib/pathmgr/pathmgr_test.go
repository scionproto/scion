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

package pathmgr

import (
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
)

// SCION test infrastructure needs to be running for this example
func ExamplePR() {
	src, _ := addr.IAFromString("1-14")
	dst, _ := addr.IAFromString("2-21")

	// Initialize path resolver
	pr, err := New("/run/shm/sciond/sd1-14.sock", time.Second, log.Root())
	if err != nil {
		fmt.Println("Failed to connect to SCIOND", "err", err)
		return
	}

	// Register source and destination
	sp, err := pr.Register(src, dst)
	if err != nil {
		fmt.Println("Failed to register", "err", err)
	}

	// sp will always point to an up to date slice of paths, or nil if none
	// available
	for i := 0; i < 20; i++ {
		paths := sp.Load()
		fmt.Printf("%#v\n", paths)
		time.Sleep(2 * time.Second)
	}
}
