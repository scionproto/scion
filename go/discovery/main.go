// Copyright 2016 ETH Zurich
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

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/samuel/go-zookeeper/zk"

	"github.com/netsec-ethz/scion/go/zkutil"
)

var zkHost = flag.String("zk-host", "127.0.0.1", "Zookeeper host")
var zkPort = flag.Int("zk-port", 2181, "Zookeeper port")
var zkTimeout = flag.Int("zk-timeout", 2000, "Zookeeper connect timeout (in ms)")

func main() {
	flag.Parse()
	targets := []string{fmt.Sprintf("%v:%v", *zkHost, *zkPort)}
	c, _, err := zk.Connect(targets, time.Millisecond*(time.Duration(*zkTimeout)))
	if err != nil {
		panic(err)
	}
	p := zkutil.NewParty(c, 1, 11, "sd1-11-2")
	err = p.Join()
	if err != nil {
		panic(err)
	}
}
