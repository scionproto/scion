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

package base

import (
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
	"github.com/netsec-ethz/scion/go/sig/metrics"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

const (
	// FrameBufPoolCap is the number of preallocated frame buffers.
	FrameBufPoolCap = 300
	// FrameBufCap is the size of a preallocated frame buffer.
	FrameBufCap = 65535
	// MaxSeqNrDist is the maximum difference between arriving sequence numbers.
	MaxSeqNrDist = 10
	// ReassemblyListCap is the maximum capacity of a reassembly list.
	ReassemblyListCap = 100
	// IngressChanSize is the length of the buffered input channel.
	IngressChanSize = 128
	// CleanUpInterval is the interval between clean up of outdated reassembly lists.
	CleanUpInterval = 1 * time.Second
)

// IngressWorker handles decapsulation of SIG frames. There is one IngressWorker per
// remote SIG.
type IngressWorker struct {
	scionNet        *scion.SCIONNet
	listenAddr      addr.HostAddr
	listenPort      uint16
	reassemblyLists map[int]*ReassemblyList
	bufPool         *sync.Pool
	c               chan *FrameBuf
}

func NewIngressWorker(scionNet *scion.SCIONNet,
	listenAddr addr.HostAddr, listenPort uint16) *IngressWorker {
	worker := &IngressWorker{
		scionNet:        scionNet,
		listenAddr:      listenAddr,
		listenPort:      listenPort,
		bufPool:         &sync.Pool{New: func() interface{} { return NewFrameBuf() }},
		reassemblyLists: make(map[int]*ReassemblyList),
		c:               make(chan *FrameBuf, IngressChanSize),
	}
	return worker
}

func (i *IngressWorker) Run() {
	var err error
	ExternalIngress, err = i.scionNet.ListenSCION(i.listenAddr, i.listenPort)
	if err != nil {
		log.Error("Unable to initialize ExternalIngress", "err", err)
		return
	}
	InternalIngress, err = xnet.ConnectTun(InternalIngressName)
	if err != nil {
		log.Error("Unable to connect to InternalIngress", "err", err)
		return
	}
	go i.Read()
	cleanupTimer := time.Tick(CleanUpInterval)
	for {
		select {
		case <-cleanupTimer:
			i.CleanUp()
		default:
			frame := <-i.c
			i.ProcessFrame(frame)
		}
	}
}

func (i *IngressWorker) Read() {
	for {
		frame := i.bufPool.Get().(*FrameBuf)
		read, err := ExternalIngress.Read(frame.raw)
		if err != nil {
			log.Error("IngressWorker: Unable to read from External Ingress", "err", err)
			// Release Frame
			frame.Reset()
			i.bufPool.Put(frame)
			continue
		}
		frame.frameLen = read
		i.c <- frame
		metrics.FramesRecv.WithLabelValues(i.scionNet.IA.String()).Inc()
		metrics.FrameBytesRecv.WithLabelValues(i.scionNet.IA.String()).Add(float64(read))
	}
}

// processFrame processes a SIG frame by first writing all completely contained
// packets to the wire and then adding the frame to the corresponding reassembly
// list if needed.
func (i *IngressWorker) ProcessFrame(frame *FrameBuf) {
	seqNr := int(common.Order.Uint32(frame.raw[:4]))
	index := int(common.Order.Uint16(frame.raw[4:6]))
	epoch := int(common.Order.Uint16(frame.raw[6:8]))
	frame.seqNr = seqNr
	frame.index = index
	//log.Debug("Received Frame", "seqNr", seqNr, "index", index, "epoch", epoch,
	//	"len", frame.frameLen)
	// If index == 1 then we can be sure that there is no fragment at the beginning
	// of the frame.
	frame.fragNProcessed = index == 1
	// If index == 0 then we can be sure that there are no complete packets in this
	// frame.
	frame.completePktsProcessed = index == 0
	// Add to frame buf reassembly list.
	rlist := i.GetReassemblyList(epoch)
	rlist.Insert(frame)
}

func (i *IngressWorker) GetReassemblyList(epoch int) *ReassemblyList {
	rlist, ok := i.reassemblyLists[epoch]
	if !ok {
		rlist = NewReassemblyList(epoch, ReassemblyListCap, i.bufPool)
		i.reassemblyLists[epoch] = rlist
	}
	rlist.markedForDeletion = false
	return rlist
}

func (i *IngressWorker) CleanUp() {
	for epoch, rlist := range i.reassemblyLists {
		if rlist.markedForDeletion {
			// Reassembly list has been marked for deletion in a previous cleanup run.
			// Remove the reassembly list from the map and then release all frames
			// back to the bufpool.
			delete(i.reassemblyLists, epoch)
			go rlist.removeAll()
		} else {
			// Mark the reassembly list for deletion. If it is not accessed between now
			// and the next cleanup interval, it will be removed.
			rlist.markedForDeletion = true
		}
	}
}

func send(packet common.RawBytes) error {
	bytesWritten, err := InternalIngress.Write(packet)
	if err != nil {
		return common.NewCError("Unable to write to Internal Ingress", "err", err,
			"length", len(packet))
	}
	metrics.PktsSent.WithLabelValues(InternalIngressName).Inc()
	metrics.PktBytesSent.WithLabelValues(InternalIngressName).Add(float64(bytesWritten))
	return nil
}
