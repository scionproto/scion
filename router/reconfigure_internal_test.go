// Copyright 2026 SCION Association
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

package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ptr"
	underlayconn "github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router/bfd"
	"github.com/scionproto/scion/router/control"
)

const (
	testInternalAddr = "198.51.100.1:30042"
	testLocalAddr    = "198.51.100.1:50000"
)

var (
	testIA       = addr.MustParseIA("1-ff00:0:110")
	testNeighbor = addr.MustParseIA("1-ff00:0:111")
)

type fakePacket struct {
	src  netip.AddrPort
	data []byte
}

// fakeConn is a BatchConn that receives what is written to in,
// and discards what it sends.
type fakeConn struct {
	in     chan fakePacket
	closed chan struct{}
	once   sync.Once
}

func (c *fakeConn) ReadBatch(msgs underlayconn.Messages) (int, error) {
	select {
	case p := <-c.in:
		msgs[0].N = copy(msgs[0].Buffers[0], p.data)
		msgs[0].Addr = net.UDPAddrFromAddrPort(p.src)
		return 1, nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *fakeConn) WriteBatch(msgs underlayconn.Messages, flags int) (int, error) {
	return len(msgs), nil
}

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// fakeOpener opens fakeConns and keeps them by remote address.
// The internal connection has the zero address.
type fakeOpener struct {
	reuseLocal bool
	failOnce   map[netip.AddrPort]bool

	mu    sync.Mutex
	conns map[netip.AddrPort]*fakeConn
}

func newFakeOpener(reuseLocal bool) *fakeOpener {
	return &fakeOpener{
		reuseLocal: reuseLocal,
		failOnce:   make(map[netip.AddrPort]bool),
		conns:      make(map[netip.AddrPort]*fakeConn),
	}
}

func (o *fakeOpener) Open(
	l netip.AddrPort, r netip.AddrPort, c *underlayconn.Config) (BatchConn, error) {

	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failOnce[r] {
		delete(o.failOnce, r)
		return nil, errors.New("open failed")
	}
	conn := &fakeConn{in: make(chan fakePacket, 1), closed: make(chan struct{})}
	o.conns[r] = conn
	return conn, nil
}

func (o *fakeOpener) UDPCanReuseLocal() bool {
	return o.reuseLocal
}

func (o *fakeOpener) conn(t *testing.T, remote string) *fakeConn {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	var a netip.AddrPort
	if remote != "" {
		a = netip.MustParseAddrPort(remote)
	}
	c := o.conns[a]
	require.NotNil(t, c, "no connection to %q", remote)
	return c
}

// newTestDP returns a dataplane with an internal interface on fake connections.
func newTestDP(t *testing.T, opener *fakeOpener) *dataPlane {
	d := newDataPlane(RunConfig{
		NumProcessors:         1,
		NumSlowPathProcessors: 1,
		BatchSize:             4,
	}, false)
	require.NoError(t, d.SetIA(testIA))
	require.NoError(t, d.SetKey(testKey))
	d.underlays["udpip"].SetConnOpener(opener)
	require.NoError(t, d.AddInternalInterface(
		hostOf(testInternalAddr), "udpip", testInternalAddr))
	return d
}

// startUnderlays starts d like Run does, but it runs no processors.
// The test reads the processor queue instead.
func startUnderlays(t *testing.T, d *dataPlane) chan *Packet {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d.initPacketPool(d.RunConfig.BatchSize)
	procQs, _ := d.initQueues(d.RunConfig.BatchSize)
	d.runCtx = ctx
	d.procQs = procQs
	d.setRunning()
	for _, u := range d.underlays {
		u.Start(ctx, d.packetPool, procQs)
	}
	return procQs[0]
}

// stopAndCheckPool stops d and checks that every packet went back to the pool.
func stopAndCheckPool(t *testing.T, d *dataPlane) {
	d.underlays["udpip"].Stop()
	assert.Equal(t, d.poolSize, len(d.packetPool.pool), "packets missing from the pool")
}

func hostOf(a string) addr.Host {
	return addr.HostIP(netip.MustParseAddrPort(a).Addr())
}

func externalLink(remote string, bfd bool) control.LinkInfo {
	return control.LinkInfo{
		Provider: "udpip",
		Local:    control.LinkEnd{IA: testIA, Addr: testLocalAddr},
		Remote:   control.LinkEnd{IA: testNeighbor, Addr: remote},
		BFD: control.BFD{
			Disable:               ptr.To(!bfd),
			DetectMult:            3,
			DesiredMinTxInterval:  time.Second,
			RequiredMinRxInterval: time.Second,
		},
	}
}

func siblingLink(sibling string) control.LinkInfo {
	return control.LinkInfo{
		Provider: "udpip",
		Local:    control.LinkEnd{IA: testIA, Addr: testInternalAddr},
		Remote:   control.LinkEnd{IA: testNeighbor, Addr: sibling},
		Instance: "br2",
		BFD:      control.BFD{Disable: ptr.To(true)},
	}
}

func addExternal(t *testing.T, d *dataPlane, ifID uint16, remote string) {
	t.Helper()
	require.NoError(t, d.AddNeighborIA(ifID, testNeighbor))
	require.NoError(t, d.AddExternalInterface(
		ifID, externalLink(remote, false), hostOf(testLocalAddr), hostOf(remote)))
}

func addSibling(t *testing.T, d *dataPlane, ifID uint16, sibling string) {
	t.Helper()
	require.NoError(t, d.AddNeighborIA(ifID, testNeighbor))
	require.NoError(t, d.AddNextHop(
		ifID, siblingLink(sibling), hostOf(testInternalAddr), hostOf(sibling)))
}

// receive makes c receive a packet from src,
// and returns the link that the packet got to the processors through.
func receive(
	t *testing.T, c *fakeConn, src string, procQ chan *Packet, d *dataPlane,
) Link {
	t.Helper()
	c.in <- fakePacket{
		src:  netip.MustParseAddrPort(src),
		data: serializedBaseMsg(t, nil, 0),
	}
	select {
	case p := <-procQ:
		defer d.packetPool.Put(p)
		return p.Link
	case <-time.After(time.Second):
		t.Fatal("packet not received")
		return nil
	}
}

func TestInterfacesChangeWhileRunning(t *testing.T) {
	opener := newFakeOpener(true)
	d := newTestDP(t, opener)
	addExternal(t, d, 1, "203.0.113.1:50000")
	procQ := startUnderlays(t, d)
	poolSize := d.poolSize

	// A new interface receives, and the pool grows for it.
	addExternal(t, d, 2, "203.0.113.2:50000")
	assert.Equal(t, poolSize+3*d.RunConfig.BatchSize, d.poolSize)
	link2 := d.table().link(2)
	require.NotNil(t, link2)
	assert.Equal(t, link2,
		receive(t, opener.conn(t, "203.0.113.2:50000"), "203.0.113.2:50000", procQ, d))

	// A removed interface stops, and its link refuses packets.
	link1 := d.table().link(1)
	require.NoError(t, d.DelInterface(1))
	assert.Nil(t, d.table().link(1))
	assert.True(t, opener.conn(t, "203.0.113.1:50000").isClosed())
	p := d.packetPool.Get()
	assert.False(t, link1.Send(p))
	d.packetPool.Put(p)

	// The neighbor moves. The packets of the removed link are enough for the new one.
	addExternal(t, d, 1, "203.0.113.11:50000")
	assert.Equal(t, poolSize+3*d.RunConfig.BatchSize, d.poolSize)
	assert.Equal(t, d.table().link(1),
		receive(t, opener.conn(t, "203.0.113.11:50000"), "203.0.113.11:50000", procQ, d))

	stopAndCheckPool(t, d)
}

// TestDelInterfaceWhileSending replaces an interface many times while others send to it.
// Packets that race with a link that stops must go back to the pool.
// The race is narrow, so a single run may miss a bug.
func TestDelInterfaceWhileSending(t *testing.T) {
	opener := newFakeOpener(true)
	d := newTestDP(t, opener)
	addExternal(t, d, 1, "203.0.113.1:50000")
	startUnderlays(t, d)
	var current atomic.Value
	current.Store(d.table().link(1))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				p := d.packetPool.Get()
				if !current.Load().(Link).Send(p) {
					d.packetPool.Put(p)
				}
			}
		})
	}
	for i := range 300 {
		require.NoError(t, d.DelInterface(1))
		addExternal(t, d, 1, fmt.Sprintf("203.0.113.%d:50000", 2+i%200))
		current.Store(d.table().link(1))
	}
	close(stop)
	wg.Wait()

	stopAndCheckPool(t, d)
}

func TestSiblingLinkStopsWithLastInterface(t *testing.T) {
	const sibling = "198.51.100.2:30042"
	for _, reuseLocal := range []bool{true, false} {
		t.Run(fmt.Sprintf("reuse local address %t", reuseLocal), func(t *testing.T) {
			opener := newFakeOpener(reuseLocal)
			d := newTestDP(t, opener)
			addSibling(t, d, 2, sibling)
			addSibling(t, d, 3, sibling)
			procQ := startUnderlays(t, d)
			lk := d.table().link(2)
			require.NotNil(t, lk)
			assert.Equal(t, lk, d.table().link(3))

			// Without connected sockets, sibling links share the internal connection.
			c := opener.conn(t, "")
			if reuseLocal {
				c = opener.conn(t, sibling)
			}

			require.NoError(t, d.DelInterface(2))
			assert.Equal(t, lk, receive(t, c, sibling, procQ, d))

			require.NoError(t, d.DelInterface(3))
			if reuseLocal {
				assert.True(t, c.isClosed())
			} else {
				assert.Equal(t, Internal, receive(t, c, sibling, procQ, d).Scope())
			}
			p := d.packetPool.Get()
			assert.False(t, lk.Send(p))
			d.packetPool.Put(p)

			stopAndCheckPool(t, d)
		})
	}
}

func TestDelInterfaceDeletesUpMetric(t *testing.T) {
	const remote = "203.0.113.1:50000"
	opener := newFakeOpener(true)
	d := newTestDP(t, opener)
	require.NoError(t, d.AddNeighborIA(4242, testNeighbor))
	require.NoError(t, d.AddExternalInterface(
		4242, externalLink(remote, true), hostOf(testLocalAddr), hostOf(remote)))
	startUnderlays(t, d)

	require.NoError(t, d.DelInterface(4242))
	labels := prometheus.Labels{"interface": "4242"}
	assert.Zero(t, d.Metrics.InterfaceUp.DeletePartialMatch(labels))

	stopAndCheckPool(t, d)
}

func TestDelInterfaceBeforeRun(t *testing.T) {
	const remote = "203.0.113.1:50000"
	opener := newFakeOpener(true)
	d := newTestDP(t, opener)
	addExternal(t, d, 1, remote)
	require.NoError(t, d.DelInterface(1))
	assert.True(t, opener.conn(t, remote).isClosed())

	// The same addresses work again.
	addExternal(t, d, 1, remote)
	procQ := startUnderlays(t, d)
	assert.Equal(t,
		d.table().link(1),
		receive(t, opener.conn(t, remote), remote, procQ, d))
	stopAndCheckPool(t, d)
}

func TestDelInterfaceErrors(t *testing.T) {
	d := newTestDP(t, newFakeOpener(true))
	assert.ErrorIs(t, d.DelInterface(0), errDelInternal)
	assert.ErrorIs(t, d.DelInterface(1), errNoSuchInterface)

	// DelInterface undoes AddNeighborIA, so that it can be called again.
	require.NoError(t, d.AddNeighborIA(1, testNeighbor))
	require.NoError(t, d.DelInterface(1))
	require.NoError(t, d.AddNeighborIA(1, testNeighbor))
}

// staticProvider is an underlay provider that is no LinkDeleter.
type staticProvider struct{}

func init() {
	AddUnderlay("static", func(int, int, int) UnderlayProvider {
		return staticProvider{}
	})
}

func (staticProvider) SetConnOpener(opener any) {}
func (staticProvider) NumConnections() int {
	return 0
}
func (staticProvider) Headroom() int {
	return 0
}
func (staticProvider) SetDispatchPorts(start, end, redirect uint16) {}
func (staticProvider) AddSvc(svc addr.SVC, host addr.Host, port uint16) error {
	return nil
}
func (staticProvider) DelSvc(svc addr.SVC, host addr.Host, port uint16) error {
	return nil
}
func (staticProvider) Start(ctx context.Context, pool PacketPool, qs []chan *Packet) {}
func (staticProvider) Stop()                                                         {}

func (staticProvider) NewExternalLink(qSize int, bfd *bfd.Session, local, remote string,
	ifID uint16, metrics *InterfaceMetrics) (Link, error) {

	return &MockLink{ifID: ifID}, nil
}

func (staticProvider) NewSiblingLink(qSize int, bfd *bfd.Session, local, remote string,
	metrics *InterfaceMetrics) (Link, error) {

	return &MockLink{}, nil
}

func (staticProvider) NewInternalLink(
	localAddr string, qSize int, metrics *InterfaceMetrics) (Link, error) {

	return &MockLink{}, nil
}

func TestLinksOfStaticProvider(t *testing.T) {
	const remote1, remote2 = "203.0.113.1:50000", "203.0.113.2:50000"
	d := newTestDP(t, newFakeOpener(true))
	link := externalLink(remote1, false)
	link.Provider = "static"
	require.NoError(t, d.AddNeighborIA(1, testNeighbor))
	require.NoError(t, d.AddExternalInterface(
		1, link, hostOf(testLocalAddr), hostOf(remote1)))
	startUnderlays(t, d)

	// Once the dataplane runs, the links stay as they are.
	link.Remote.Addr = remote2
	require.NoError(t, d.AddNeighborIA(2, testNeighbor))
	assert.ErrorIs(t, d.AddExternalInterface(
		2, link, hostOf(testLocalAddr), hostOf(remote2)), errNoReload)
	assert.Nil(t, d.table().link(2))
	assert.ErrorIs(t, d.DelInterface(1), errNoReload)
	assert.NotNil(t, d.table().link(1))

	stopAndCheckPool(t, d)
}

func TestConnectorRetriesFailedAdd(t *testing.T) {
	const remote = "203.0.113.5:50000"
	opener := newFakeOpener(true)
	opener.failOnce[netip.MustParseAddrPort(remote)] = true
	c := &Connector{DataPlane: makeDataPlane(RunConfig{
		NumProcessors: 1,
		BatchSize:     4}, false),
	}
	c.DataPlane.underlays["udpip"].SetConnOpener(opener)
	require.NoError(t, c.CreateIACtx(testIA))
	require.NoError(t, c.AddInternalInterface(
		testIA, hostOf(testInternalAddr), "udpip", testInternalAddr))

	link := externalLink(remote, false)
	assert.Error(t, c.AddExternalInterface(
		5, link, hostOf(testLocalAddr), hostOf(remote), true,
	))
	ifs, err := c.ListExternalInterfaces()
	require.NoError(t, err)
	assert.Empty(t, ifs)

	require.NoError(t,
		c.AddExternalInterface(5, link, hostOf(testLocalAddr), hostOf(remote), true))
	ifs, err = c.ListExternalInterfaces()
	require.NoError(t, err)
	assert.Len(t, ifs, 1)

	require.NoError(t, c.DelExternalInterface(5))
	ifs, err = c.ListExternalInterfaces()
	require.NoError(t, err)
	assert.Empty(t, ifs)
}
