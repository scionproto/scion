// Copyright 2026 ETH Zurich
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

//go:build testhooks

// These tests and benchmarks rely on accessing the internals of the router package.
// To run them, the build tag "testhooks" must be provided. E.g.
// go test -tags=testhooks ./router/underlayproviders/udpip/

package udpip

import (
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/pkg/log"

	"github.com/scionproto/scion/pkg/slices"
	"github.com/scionproto/scion/private/underlay/conn"
	underlayconn "github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/mock_router"
)

func TestReadUpTo(t *testing.T) {
	const batchSize = 256
	const N = 1024 * 1024
	t.Run("new", func(t *testing.T) {
		queues := createQueues(batchSize)
		go func() {
			for range N {
				queues[1] <- &router.Packet{}
			}
			close(queues[0])
			close(queues[1])
		}()
		pkts := make([]*router.Packet, batchSize)
		iter := slices.CDIterator(pkts, 0, len(pkts))
		for rem := N; rem > 0; {
			read := readUpTo(iter, queues, true)
			rem -= read
		}
	})
	t.Run("old", func(t *testing.T) {
		ch := make(chan *router.Packet, batchSize)
		go func() {
			for range N {
				ch <- &router.Packet{}
			}
			close(ch)
		}()
		pkts := make([]*router.Packet, batchSize)

		for rem := N; rem > 0; {
			read := oldReadUpTo(ch, batchSize, true, pkts)
			rem -= read
		}
	})
}

func TestSend(t *testing.T) {
	const PacketsToSendCount = 1024 * 1024

	t.Run("new", func(t *testing.T) {
		u := createUdpConnection(t, 256)
		pool := router.MakePacketPool(256, 0)

		// Send some packets.
		go func() {
			for range PacketsToSendCount {
				pkt := pool.Get()
				u.queues[1] <- pkt
			}
			// Stop the forwarder.
			u.running.Store(false)
			for _, q := range u.queues {
				close(q)
			}
			u.conn.Close()
		}()

		// Run the forwarding process.
		u.send(256, pool)
	})

	t.Run("old", func(t *testing.T) {
		u := createUdpConnection(t, 256)
		pool := router.MakePacketPool(256, 0)

		// Send some packets.
		go func() {
			for range PacketsToSendCount {
				pkt := pool.Get()
				u.queues[1] <- pkt
			}
			// Stop the forwarder.
			u.running.Store(false)
			for _, q := range u.queues {
				close(q)
			}
			u.conn.Close()
		}()

		// Run the forwarding process.
		u.oldSend(256, pool)
	})
}

func BenchmarkReadUpTo(b *testing.B) {
	const batchSize = 256
	const N = 1024

	b.Run("old", func(b *testing.B) {
		for range b.N {
			ch := make(chan *router.Packet, batchSize)
			go func() {
				for range N {
					ch <- &router.Packet{}
				}
				close(ch)
			}()
			pkts := make([]*router.Packet, batchSize)
			for rem := N; rem > 0; {
				read := oldReadUpTo(ch, batchSize, true, pkts)
				rem -= read
			}
		}
	})

	b.Run("new", func(b *testing.B) {
		for range b.N {
			queues := createQueues(batchSize)
			go func() {
				for range N {
					queues[1] <- &router.Packet{}
				}
				close(queues[0])
				close(queues[1])
			}()
			pkts := make([]*router.Packet, batchSize)
			iter := slices.CDIterator(pkts, 0, len(pkts))
			for rem := N; rem > 0; {
				read := readUpTo(iter, queues, true)
				rem -= read
			}
		}
	})

}

// cpu: Intel(R) Core(TM) i7-7700T CPU @ 2.90GHz
// BenchmarkSend/old-8                 5379            283566 ns/op
// BenchmarkSend/new-8                 3517            367717 ns/op
func BenchmarkSend(b *testing.B) {
	const batchSize = 256
	const PacketsToSend = 1024

	b.Run("old", func(b *testing.B) {
		for range b.N {
			b.StopTimer()
			u := createUdpConnection(b, batchSize)
			pool := router.MakePacketPool(batchSize, 0)

			// Send some packets.
			go func() {
				for range PacketsToSend {
					pkt := pool.Get()
					u.queues[1] <- pkt
				}
				// Stop the forwarder.
				u.running.Store(false)
				for _, q := range u.queues {
					close(q)
				}
				u.conn.Close()
			}()
			b.StartTimer()
			u.oldSend(256, pool)
		}
	})

	b.Run("new", func(b *testing.B) {
		for range b.N {
			b.StopTimer()
			u := createUdpConnection(b, batchSize)
			pool := router.MakePacketPool(batchSize, 0)

			// Send some packets.
			go func() {
				for range PacketsToSend {
					pkt := pool.Get()
					u.queues[1] <- pkt
				}
				// Stop the forwarder.
				u.running.Store(false)
				for _, q := range u.queues {
					close(q)
				}
				u.conn.Close()
			}()
			b.StartTimer()
			u.send(256, pool)
		}
	})
}

func oldReadUpTo(queue <-chan *router.Packet, n int, needsBlocking bool, pkts []*router.Packet) int {
	i := 0
	if needsBlocking {
		p, ok := <-queue
		if !ok {
			return i
		}
		pkts[i] = p
		i++
	}

	for ; i < n; i++ {
		select {
		case p, ok := <-queue:
			if !ok {
				return i
			}
			pkts[i] = p
		default:
			return i
		}
	}
	return i
}

func (u *udpConnection) oldSend(batchSize int, pool router.PacketPool) {
	log.Debug("Send", "connection", u.name)

	// We use this somewhat like a ring buffer.
	pkts := make([]*router.Packet, batchSize)

	// We use this as a temporary buffer, but allocate it just once
	// to save on garbage handling.
	msgs := make(conn.Messages, batchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
	}

	queue := u.queues[1]
	conn := u.conn
	metrics := u.metrics
	toWrite := 0

	for u.running.Load() {
		// Top-up our batch.
		toWrite += oldReadUpTo(queue, batchSize-toWrite, toWrite == 0, pkts[toWrite:])

		// Turn the packets into underlay messages that WriteBatch can send.
		for i, p := range pkts[:toWrite] {
			msgs[i].Buffers[0] = p.RawPacket
			msgs[i].Addr = nil
			// If we're using a connected socket we must not specify the address. It might cause
			// redundant route queries and the address might not even be set in the packet.
			// Otherwise, we must specify the address.
			if !u.connected {
				msgs[i].Addr = (*net.UDPAddr)(p.RemoteAddr)
			}
		}

		written, _ := conn.WriteBatch(msgs[:toWrite], 0)
		if written < 0 {
			// WriteBatch returns -1 on error, we just consider this as
			// 0 packets written
			written = 0
		}
		oldUpdateOutputMetrics(metrics, pkts[:written])
		for _, p := range pkts[:written] {
			pool.Put(p)
		}
		if written != toWrite {
			// Only one is dropped at this time. We'll retry the rest.
			sc := router.ClassOfSize(len(pkts[written].RawPacket))
			metrics[sc].DroppedPacketsInvalid.Inc()
			pool.Put(pkts[written])
			toWrite -= (written + 1)
			// Shift the leftovers to the head of the buffers.
			for i := 0; i < toWrite; i++ {
				pkts[i] = pkts[i+written+1]
			}
		} else {
			toWrite = 0
		}
	}
}

func oldUpdateOutputMetrics(metrics *router.InterfaceMetrics, packets []*router.Packet) {
	// We need to collect stats by traffic type and size class.
	// Try to reduce the metrics lookup penalty by using some
	// simpler staging data structure.
	writtenPkts := [router.TtMax][router.MaxSizeClass]int{}
	writtenBytes := [router.TtMax][router.MaxSizeClass]int{}
	for _, p := range packets {
		s := len(p.RawPacket)
		sc := router.ClassOfSize(s)
		tt := p.GetTrafficType()
		writtenPkts[tt][sc]++
		writtenBytes[tt][sc] += s
	}
	for t := router.TtOther; t < router.TtMax; t++ {
		for sc := router.MinSizeClass; sc < router.MaxSizeClass; sc++ {
			if writtenPkts[t][sc] > 0 {
				metrics[sc].Output[t].OutputPacketsTotal.Add(float64(writtenPkts[t][sc]))
				metrics[sc].Output[t].OutputBytesTotal.Add(float64(writtenBytes[t][sc]))
			}
		}
	}
}

func createUdpConnection(t gomock.TestReporter, queueSize int) *udpConnection {
	ctrl := gomock.NewController(t)
	mConn := mock_router.NewMockBatchConn(ctrl)
	mConn.EXPECT().WriteBatch(gomock.Any(), 0).AnyTimes().DoAndReturn(
		func(msgs underlayconn.Messages, flags int) (int, error) {
			// fmt.Printf("sent %d packets\n", len(msgs))
			time.Sleep(time.Duration(len(msgs)) * time.Nanosecond)
			return len(msgs), nil
		})
	mConn.EXPECT().Close().AnyTimes().Return(nil)

	metrics := &router.InterfaceMetrics{}
	noOpts := prometheus.CounterOpts{}
	for i := range metrics {
		metrics[i].DroppedPacketsInvalid = prometheus.NewCounter(noOpts)
		for j := range 6 {
			metrics[i].Output[j].OutputBytesTotal = prometheus.NewCounter(noOpts)
			metrics[i].Output[j].OutputPacketsTotal = prometheus.NewCounter(noOpts)
		}
	}
	u := &udpConnection{
		queues:  createQueues(queueSize),
		conn:    mConn,
		metrics: metrics,
	}
	u.running.Store(true)
	return u
}
