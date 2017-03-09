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

// This file defines the data structures used to manage the SCMPAuth DRKeys.
// TODO(roosd): allow changing master secrets

package rpkt

import (
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/scion/go/lib/common"
	"sync"
)

//////////////////////////////////
// Type definitions
//////////////////////////////////

//// Present SCMPAuth DRKeys:

// SCMPAuthDRKeys is a store for available SCMPAuth DRKeys.
type SCMPAuthDRKeys struct {
	sync.RWMutex
	// Mapping from ISD-AS to SCMPAuth DRKey.
	Map map[uint32]common.RawBytes
	// Channel used to communicate with the HandleSCMPAuthDRKeyReplies go routine.
	Channel chan SCMPAuthDRKeyReplyElement
}

// SCMPAuthDRKeyReplyElement is the basic building block for SCMPAuthDRKeys.
type SCMPAuthDRKeyReplyElement struct {
	IsdAs uint32
	DRKey common.RawBytes
}

//// Missing SCMPAuth DRKeys:

// MissingSCMPAuthDRKeys is a store for missing SCMPAuth DRKeys.
type MissingSCMPAuthDRKeys struct {
	sync.RWMutex
	// Map used for fast set membership queries.
	Map map[uint32]*MissingSCMPAuthDRKeyElement
	// Channel used for communication with the RequestSCMPAuthDRKeys go routine.
	Channel chan uint32
	// Pool of unused MissingSCMPAuthDRKeyElements
	freeList chan *MissingSCMPAuthDRKeyElement
	// Block allocation of MissingSCMPAuthDRKeyElements
	elements []MissingSCMPAuthDRKeyElement
	// Head of request list.
	head *MissingSCMPAuthDRKeyElement
	// Tail of request list.
	tail *MissingSCMPAuthDRKeyElement
}

// MissingSCMPAuthDRKeyElement is the basic building block MissingSCMPAuthDRKeys.
type MissingSCMPAuthDRKeyElement struct {
	// ISD-AS
	IsdAs uint32
	// Time of insertion into the queue.
	InsertionTime int64
	// prev element in request list.
	prev *MissingSCMPAuthDRKeyElement
	// next element in request list.
	next *MissingSCMPAuthDRKeyElement
}

///// Packet buffer:

// SCMPAuthQueues is the packet buffer management data structure.
// The locking order is SCMPAuthQueues -> SCMPAuthQueue, meaning to lock a queue individually, either a read or a write
// lock over whole data structure has to be obtained.
type SCMPAuthQueues struct {
	// Lock for Map
	sync.RWMutex
	// List of all queues.
	queues []*SCMPAuthQueue
	// Mapping from ISD-AS to the corresponding packet buffer.
	Map map[uint32]*SCMPAuthQueue
	// List of empty queues.
	emptyQueues []*SCMPAuthQueue
	// Channel used to forward packets back to the router to be reprocessed.
	RtrPktChannel chan *RtrPkt
}

// SCMPAuthQueue a packet buffer.
type SCMPAuthQueue struct {
	sync.RWMutex
	// Slice of the router packets
	Rpkts []*RtrPkt
	// Indicates if queue is free. Used to detect race conditions.
	Free bool
}

//////////////////////////////////
// Constructors
//////////////////////////////////

func NewSCMPAuthDRKeys() *SCMPAuthDRKeys {
	m := &SCMPAuthDRKeys{
		Map:     make(map[uint32]common.RawBytes),
		Channel: make(chan SCMPAuthDRKeyReplyElement, 100),
	}
	return m
}

func NewMissingSCMPAuthDRKeys(queueSize int) *MissingSCMPAuthDRKeys {
	m := &MissingSCMPAuthDRKeys{
		Map:      make(map[uint32]*MissingSCMPAuthDRKeyElement, queueSize),
		Channel:  make(chan uint32, queueSize),
		freeList: make(chan *MissingSCMPAuthDRKeyElement, queueSize),
		elements: make([]MissingSCMPAuthDRKeyElement, queueSize),
		head:     nil,
		tail:     nil,
	}

	for i := 0; i < len(m.elements); i++ {
		m.freeList <- &m.elements[i]
	}

	return m
}

func NewSCMPAuthQueues(numQueues int, maxQueueSize int) *SCMPAuthQueues {
	s := &SCMPAuthQueues{
		Map:           make(map[uint32]*SCMPAuthQueue, numQueues),
		queues:        make([]*SCMPAuthQueue, numQueues),
		emptyQueues:   make([]*SCMPAuthQueue, numQueues),
		RtrPktChannel: make(chan *RtrPkt),
	}

	for i := 0; i < len(s.queues); i++ {
		s.queues[i] = &SCMPAuthQueue{Rpkts: make([]*RtrPkt, 0, maxQueueSize)}
		s.emptyQueues[i] = s.queues[i]
	}
	return s
}

//////////////////////////////////
// Missing SCMP Auth DRKey functions
//////////////////////////////////

// Append appends a MissingSCMPAuthDRKeyElement to the request queue.
// Assumptions: -Caller has write lock
//		-isdAs not already in Queue
func (m *MissingSCMPAuthDRKeys) Append(elem *MissingSCMPAuthDRKeyElement) {
	switch {
	case m.head == nil:
		m.head = elem
		elem.prev = nil
	default:
		m.tail.next = elem
		elem.prev = m.tail
	}

	m.tail = elem
	m.tail.next = nil
	m.Map[elem.IsdAs] = elem
}

// Peak returns the first MissingSCMPAuthDRKeyElement in the request queue. This element will be the oldest.
// Assumptions: -Caller has read lock
func (m *MissingSCMPAuthDRKeys) Peak() *MissingSCMPAuthDRKeyElement {
	return m.head
}

// Pop returns the first MissingSCMPAuthDRKeyElement in the request queue and removes it.
// This element will be the oldest.
// Assumptions: -Caller has write lock
func (m *MissingSCMPAuthDRKeys) Pop() *MissingSCMPAuthDRKeyElement {
	elem := m.head
	if m.head != nil {
		delete(m.Map, elem.IsdAs)
		m.head = m.head.next
		if m.head != nil {
			m.head.prev = nil
		}
	}
	if m.tail == elem {
		m.tail = nil
	}
	return elem
}

// Remove deletes the MissingSCMPAuthDRKeyElement corresponding to the ISD-AS from the request queue.
// Assumptions: -Caller has write lock
func (m *MissingSCMPAuthDRKeys) Remove(isdAs uint32) *MissingSCMPAuthDRKeyElement {
	if elem, ok := m.Map[isdAs]; ok {
		delete(m.Map, elem.IsdAs)
		switch {
		case m.head == elem && m.tail == elem:
			m.head = nil
			m.tail = nil
		case m.head == elem:
			m.head = m.head.next
			m.head.prev = nil
		case m.tail == elem:
			m.tail = m.tail.prev
			m.tail.next = nil
		default:
			elem.prev.next = elem.next
			elem.next.prev = elem.prev
		}
		return elem
	}
	return nil

}

// GetFreeIfNotPresent returns a unused MissingSCMPAuthDRKeyElement if the ISD-AS has not already a pending request.
func (m *MissingSCMPAuthDRKeys) GetFreeIfNotPresent(isdAS uint32) (*MissingSCMPAuthDRKeyElement, bool) {
	if _, present := m.Map[isdAS]; !present {
		select {
		case free := <-m.freeList:
			return free, present
		default:
			return nil, present
		}
	}
	return nil, true
}

// RecycleFree reclaims the ownership of a no longer used MissingSCMPAuthDRKeyElement.
func (m *MissingSCMPAuthDRKeys) RecycleFree(free *MissingSCMPAuthDRKeyElement) {
	select {
	case m.freeList <- free:
	default:
		log.Error("Cannot recycle free MissingSCMPAuthDRKeyElement. PANIC")
	}
}

//////////////////////////////////
// Packet buffer functions
//////////////////////////////////

// AddQueue adds a queue to Map and returns the success.
// Assumptions: -Caller has write lock.
// 		-ISD-AS is not in mapping.
func (s *SCMPAuthQueues) AddQueue(isdAs uint32) bool {
	if lastIndex := len(s.emptyQueues) - 1; lastIndex >= 0 {
		emptyQueue := s.emptyQueues[lastIndex]
		s.emptyQueues = s.emptyQueues[:lastIndex]
		emptyQueue.Rpkts = emptyQueue.Rpkts[:0]
		emptyQueue.Free = false
		s.Map[isdAs] = emptyQueue
		return true
	}
	return false
}

// PopQueue returns the SCMPAuthQueue corresponding to ISD-AS and removes it from Map.
// Assumptions: -Caller has write lock.
func (s *SCMPAuthQueues) PopQueue(isdAs uint32) *SCMPAuthQueue {
	if queue, ok := s.Map[isdAs]; ok {
		delete(s.Map, isdAs)
		return queue
	}
	return nil
}

// RecycleQueue reclaims ownership of no longer used SCMPAuthQueue.
// Assumption: -Caller has write lock.
func (s *SCMPAuthQueues) RecycleQueue(queue *SCMPAuthQueue) {
	queue.Free = true
	s.emptyQueues = append(s.emptyQueues, queue)
}
