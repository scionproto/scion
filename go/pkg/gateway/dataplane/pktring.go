// Copyright 2020 Anapaya Systems
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

package dataplane

import "github.com/scionproto/scion/go/lib/ringbuf"

const (
	batchSize = 32
	ringSize  = 64
)

// pktRing reads entries from a ringbuffer in batches but hands them to
// the client one by one.
type pktRing struct {
	// ring is the undelying ringbuffer.
	ring *ringbuf.Ring
	// storage is an array to store the buffered entries in.
	storage [batchSize]ringbuf.Entry
	// entries are the buffered entries. A slice on top of the storage.
	entries []ringbuf.Entry
}

// newPktRing creates a new packet ring.
func newPktRing() *pktRing {
	ring := ringbuf.New(ringSize, nil, "egress")
	return &pktRing{ring: ring}
}

// Write writes one packet to the ringbuffer.
// Returns 1 if successful, 0 if the call would block or -1 if the ringbuf was closed.
func (pr *pktRing) Write(pkt []byte, block bool) int {
	n, _ := pr.ring.Write(ringbuf.EntryList{pkt}, block)
	return n
}

// Read returns next packet from the ringbuffer.
// Returns 1 if successful, 0 if the call would block or -1 if the ringbuf was closed.
func (pr *pktRing) Read(block bool) ([]byte, int) {
	if len(pr.entries) == 0 {
		pr.entries = pr.storage[:]
		n, _ := pr.ring.Read(pr.entries, block)
		if n == -1 {
			// Ringbuffer closed.
			pr.entries = pr.storage[:0]
			return nil, -1
		}
		if n == 0 {
			// There's no data in the ringbuffer.
			pr.entries = pr.storage[:0]
			return nil, 0
		}
		pr.entries = pr.storage[:n]
	}
	pkt := pr.entries[0].([]byte)
	pr.entries = pr.entries[1:]
	return pkt, 1
}

// Close closes the ring. This causes the Read function to return nil.
func (pr *pktRing) Close() {
	pr.ring.Close()
}
