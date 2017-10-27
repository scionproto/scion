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

package pathmgr

import (
	"flag"
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

var (
	srcStr = flag.String("srcIA", "1-14", "Source ISD-AS")
	dstStr = flag.String("dstIA", "2-21", "Destination ISD-AS")
)

// SCION test infrastructure needs to be running for this example.
func ExamplePR() {
	// Run with "go test -tags=infrarunning -args -srcIA 1-14 -dstIA 2-21".
	var err error
	src, err := addr.IAFromString(*srcStr)
	if err != nil {
		fmt.Println("Unable to parse srcIA", *srcStr, "err", err)
	}
	dst, err := addr.IAFromString(*dstStr)
	if err != nil {
		fmt.Println("Unable to parse dstIA", *dstStr, "err", err)
	}
	// Initialize path resolver
	sciondPath := fmt.Sprintf("/run/shm/sciond/sd%s.sock", src.String())
	sciondService := sciond.NewService(sciondPath)
	pr, err := New(sciondService, time.Second, time.Minute, log.Root())
	if err != nil {
		fmt.Println("Failed to connect to SCIOND", "err", err)
		return
	}
	// Register source and destination
	sp, err := pr.Watch(src, dst)
	if err != nil {
		fmt.Println("Failed to register", "err", err)
	}
	// sp will always point to an up to date slice of paths, or nil if none
	// available
	for i := 0; i < 5; i++ {
		paths := sp.Load().APS
		if len(paths) > 0 {
			fmt.Printf("!")
		} else {
			fmt.Printf(".")
		}
		time.Sleep(2 * time.Second)
	}
	// Output: !!!!!
}
