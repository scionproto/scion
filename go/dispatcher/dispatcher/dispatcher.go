package dispatcher

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/dispatcher/internal/metrics"
	"github.com/scionproto/scion/go/dispatcher/internal/registration"
	"github.com/scionproto/scion/go/dispatcher/internal/respool"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/underlay/conn"
)

// OverflowLoggingInterval is the minimum amount of time that needs to
// pass before another overflow logging message is printed (if needed).
const OverflowLoggingInterval = 10 * time.Second

// ReceiveBufferSize is the size of receive buffers used by the dispatcher.
const ReceiveBufferSize = 1 << 20

// Server is the main object allowing to create new SCION connections.
type Server struct {
	// routingTable is used to register new connections.
	routingTable *IATable
	ipv4Conn     net.PacketConn
	ipv6Conn     net.PacketConn
}

// NewServer creates new instance of Server. Internally, it opens the dispatcher ports
// for both IPv4 and IPv6. Returns error if the ports can't be opened.
func NewServer(address string, ipv4Conn, ipv6Conn net.PacketConn) (*Server, error) {
	metaLogger := &throttledMetaLogger{
		Logger:      log.Root(),
		MinInterval: OverflowLoggingInterval,
	}
	if ipv4Conn == nil {
		var err error
		ipv4Conn, err = openConn("udp4", address, metaLogger)
		if err != nil {
			return nil, err
		}
	}
	if ipv6Conn == nil {
		var err error
		ipv6Conn, err = openConn("udp6", address, metaLogger)
		if err != nil {
			ipv4Conn.Close()
			return nil, err
		}
	}
	return &Server{
		routingTable: NewIATable(32768, 65535),
		ipv4Conn:     ipv4Conn,
		ipv6Conn:     ipv6Conn,
	}, nil
}

// Serve starts reading packets from network and dispatching them to different connections.
// The function blocks and returns if there's an error or when Close has been called.
func (as *Server) Serve() error {
	errChan := make(chan error)
	go func() {
		defer log.HandlePanic()
		netToRingDataplane := &NetToRingDataplane{
			UnderlayConn: as.ipv4Conn,
			RoutingTable: as.routingTable,
		}
		errChan <- netToRingDataplane.Run()
	}()
	go func() {
		defer log.HandlePanic()
		netToRingDataplane := &NetToRingDataplane{
			UnderlayConn: as.ipv6Conn,
			RoutingTable: as.routingTable,
		}
		errChan <- netToRingDataplane.Run()
	}()
	return <-errChan
}

// Register creates a new connection.
func (as *Server) Register(ctx context.Context, ia addr.IA, address *net.UDPAddr,
	svc addr.HostSVC) (net.PacketConn, uint16, error) {

	tableEntry := newTableEntry()
	ref, err := as.routingTable.Register(ia, address, nil, svc, tableEntry)
	if err != nil {
		return nil, 0, err
	}
	var ovConn net.PacketConn
	if address.IP.To4() == nil {
		ovConn = as.ipv6Conn
	} else {
		ovConn = as.ipv4Conn
	}
	conn := &Conn{
		conn:         ovConn,
		ring:         tableEntry.appIngressRing,
		regReference: ref,
	}
	return conn, uint16(ref.UDPAddr().Port), nil
}

func (as *Server) Close() {
	as.ipv4Conn.Close()
	as.ipv6Conn.Close()
}

// Conn represents a connection bound to a specific SCION port/SVC.
type Conn struct {
	// conn is used to send packets.
	conn net.PacketConn
	// ring is used to retrieve incoming packets.
	ring *ringbuf.Ring
	// regReference is the reference to the registration in the routing table.
	regReference registration.RegReference
}

func (ac *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	panic("not implemented")
}

// Write is optimized for the use by ConnHandler (avoids reparsing the packet).
func (ac *Conn) Write(pkt *respool.Packet) (int, error) {
	// XXX(roosd): Ignore error since there is nothing we can do about it.
	// Currently, the ID space is shared between all applications that register
	// with the dispatcher. Likelihood that they overlap is very small.
	// If this becomes ever a problem, we can namespace the ID per registered
	// application.
	registerIfSCMPInfo(ac.regReference, pkt)
	return pkt.SendOnConn(ac.conn, pkt.UnderlayRemote)
}

func (ac *Conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	pkt := ac.Read()
	if pkt == nil {
		return 0, nil, serrors.New("Connection closed")
	}
	n = pkt.CopyTo(p)
	addr = pkt.UnderlayRemote
	pkt.Free()
	return
}

// Read is optimized for the use by ConnHandler (avoids one copy).
func (ac *Conn) Read() *respool.Packet {
	entries := make(ringbuf.EntryList, 1)
	n, _ := ac.ring.Read(entries, true)
	if n < 0 {
		// Ring was closed because app shut down its data socket.
		return nil
	}
	pkt := entries[0].(*respool.Packet)
	return pkt
}

func (ac *Conn) Close() error {
	ac.regReference.Free()
	ac.ring.Close()
	return nil
}

func (ac *Conn) LocalAddr() net.Addr {
	return ac.regReference.UDPAddr()
}

func (ac *Conn) SVCAddr() addr.HostSVC {
	return ac.regReference.SVCAddr()
}

func (ac *Conn) SetDeadline(t time.Time) error {
	panic("not implemented")
}

func (ac *Conn) SetReadDeadline(t time.Time) error {
	panic("not implemented")
}

func (ac *Conn) SetWriteDeadline(t time.Time) error {
	panic("not implemented")
}

// openConn opens an underlay socket that tracks additional socket information
// such as packets dropped due to buffer full.
//
// Note that Go-style dual-stacked IPv4/IPv6 connections are not supported. If
// network is udp, it will be treated as udp4.
func openConn(network, address string, p SocketMetaHandler) (net.PacketConn, error) {
	// We cannot allow the Go standard library to open both types of sockets
	// because the socket options are specific to only one socket type, so we
	// degrade udp to only udp4.
	if network == "udp" {
		network = "udp4"
	}
	listeningAddress, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, common.NewBasicError("unable to construct UDP addr", err)
	}
	if network == "udp4" && listeningAddress.IP == nil {
		listeningAddress.IP = net.IPv4zero
	}
	if network == "udp6" && listeningAddress.IP == nil {
		listeningAddress.IP = net.IPv6zero
	}

	c, err := conn.New(listeningAddress, nil, &conn.Config{ReceiveBufferSize: ReceiveBufferSize})
	if err != nil {
		return nil, common.NewBasicError("unable to open conn", err)
	}

	return &underlayConnWrapper{Conn: c, Handler: p}, nil
}

// registerIfSCMPInfo registers the ID of the SCMP request if it is an echo or
// traceroute message.
func registerIfSCMPInfo(ref registration.RegReference, pkt *respool.Packet) error {
	if pkt.L4 != slayers.LayerTypeSCMP {
		return nil
	}
	t := pkt.SCMP.TypeCode.Type()
	if t != slayers.SCMPTypeEchoRequest && t != slayers.SCMPTypeTracerouteRequest {
		return nil
	}
	id, err := extractSCMPIdentifier(&pkt.SCMP)
	if err != nil {
		return err
	}
	// FIXME(roosd): add metrics again.
	return ref.RegisterID(uint64(id))
}

// underlayConnWrapper wraps a specialized underlay conn into a net.PacketConn
// implementation. Only *net.UDPAddr addressing is supported.
type underlayConnWrapper struct {
	// Conn is the wrapped underlay connection object.
	conn.Conn
	// Handler is used to customize how the connection treats socket
	// metadata.
	Handler SocketMetaHandler
}

func (o *underlayConnWrapper) ReadFrom(p []byte) (int, net.Addr, error) {
	n, meta, err := o.Conn.Read(common.RawBytes(p))
	if meta == nil {
		return n, nil, err
	}
	o.Handler.Handle(meta)
	return n, meta.Src, err
}

func (o *underlayConnWrapper) WriteTo(p []byte, a net.Addr) (int, error) {
	udpAddr, ok := a.(*net.UDPAddr)
	if !ok {
		return 0, common.NewBasicError("address is not UDP", nil, "addr", a)
	}
	return o.Conn.WriteTo(common.RawBytes(p), udpAddr)
}

func (o *underlayConnWrapper) Close() error {
	return o.Conn.Close()
}

func (o *underlayConnWrapper) LocalAddr() net.Addr {
	return o.Conn.LocalAddr()
}

func (o *underlayConnWrapper) SetDeadline(t time.Time) error {
	return o.Conn.SetDeadline(t)
}

func (o *underlayConnWrapper) SetReadDeadline(t time.Time) error {
	return o.Conn.SetReadDeadline(t)
}

func (o *underlayConnWrapper) SetWriteDeadline(t time.Time) error {
	return o.Conn.SetWriteDeadline(t)
}

// SocketMetaHandler processes OS socket metadata during reads.
type SocketMetaHandler interface {
	Handle(*conn.ReadMeta)
}

// throttledMetaLogger logs packets dropped due to full receive buffers,
// with a configurable threshold on how often logging messages are printed.
type throttledMetaLogger struct {
	// Logger is used to print the logging messages.
	Logger log.Logger
	// MinInterval is the minimum duration of time that has passed since the
	MinInterval time.Duration

	mu sync.Mutex
	// lastPrintTimestamp is the time when the previous logging message was
	// printed.
	lastPrintTimestamp time.Time
	// lastPrintValue is the overflow value printed in the last logging message.
	lastPrintValue uint32
}

func (p *throttledMetaLogger) Handle(m *conn.ReadMeta) {
	p.mu.Lock()
	if m.RcvOvfl != p.lastPrintValue && time.Since(p.lastPrintTimestamp) > p.MinInterval {
		if m.RcvOvfl > p.lastPrintValue {
			metrics.M.NetReadOverflows().Add(float64(m.RcvOvfl - p.lastPrintValue))
		} else {
			metrics.M.NetReadOverflows().Add(float64(m.RcvOvfl))
		}
		p.Logger.Debug("Detected socket overflow", "total_cnt", m.RcvOvfl)
		p.lastPrintTimestamp = time.Now()
		p.lastPrintValue = m.RcvOvfl
	}
	p.mu.Unlock()
}
