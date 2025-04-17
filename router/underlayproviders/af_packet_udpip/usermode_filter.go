// Copyright 2025 SCION Association
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

package af_packet_udpip

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	_ "github.com/cilium/ebpf" // Hint to gazelle. Generated code uses it.
	"github.com/cilium/ebpf/link"
)

func initBpf(ifname string, portNum int, sockFd int) {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs bpf_filterObjects
	if err := loadBpf_filterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// TODO(jiceatscion): here we need to be more careful. The recipient socket is already
	// listening and it could receive packets that it shouldn't during the interval. Ideally
	// there should be a pass-everything map attached to this interface BEFORE we even open
	// it for our own purpose. Then, open the socket. Then, update the map with that socket as
	// the reciient for the port. Not sure about how to update the map once attached.

	// Insert our recipient socket in the map; associated with its designated port number.
	objs.SockMapRx.Put(portNum, sockFd)

	// Attach the filter to the designated network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
