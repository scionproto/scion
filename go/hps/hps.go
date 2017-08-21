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

package main

import (
	"flag"
	"os"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/hpkt"
	"github.com/netsec-ethz/scion/go/lib/spkt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/snet"
)

var (
	id    = flag.String("id", "", "Element ID (Required. E.g. 'hps4-21-9')")
	isdas = flag.String("isdas", "", "Local AS (in ISD-AS format, e.g., 1-10)")
)

func main() {
	flag.Parse()
	if *id == "" {
		log.Crit("No element ID specified")
		os.Exit(1)
	}
	liblog.Setup(*id)
	defer liblog.PanicLog()

	ia, cerr := addr.IAFromString(*isdas)
	if cerr != nil {
		log.Error("Unable to parse local AS", "isdas", *isdas, "err", cerr)
		os.Exit(1)
	}
	log.Debug("HPS started", "id", id, "IA", ia)
	go receive()
}

// receive is the main SCION packet handling loop.
func receive() {
	socket, err := snet.ListenSCION("udp", addr)
	if err != nil {
		panic("Couldn't create socket")
	}
	// Main loop
	readBuf := make(common.RawBytes, 1<<16)
	for {
		// Reset readBuf
		readBuf = readBuf[:cap(readBuf)]
		read, a, err := socket.ReadFromSCION(readBuf)
		if err != nil {
			log.Error("Error reading from socket.", "conn", socket, "err", err)
			continue
		}
		// Slice readBuf
		readBuf = readBuf[:read]
		// Parse SCION packet
		sPkt := hpkt.AllocScnPkt()
		if err := hpkt.ParseScnPkt(sPkt, readBuf); err != nil {
			log.Error("Error parsing SCION packet.", "err", err)
			continue
		}
		// Parse payload.
		cpld, err := spkt.NewCtrlPldFromRaw(sPkt.Pld)

	}
}
