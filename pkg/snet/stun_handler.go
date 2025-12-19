package snet

import (
	"context"
	"github.com/scionproto/scion/pkg/stun"
	"golang.org/x/sync/errgroup"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

const timeoutDuration = 5 * time.Minute

// stunHandler is a wrapper around net.UDPConn that handles STUN requests.
type stunHandler struct {
	*net.UDPConn
	recvChan             chan bufferedPacket
	queuedBytes          atomic.Int64
	maxQueuedBytes       int64
	recvStunChan         chan []byte
	mappings             map[*net.UDPAddr]*natMapping // TODO: necessary to protect with mutex?
	retransmissionTimers map[*net.UDPAddr]*retransmissionTimer
	writeDeadline        time.Time
}

type bufferedPacket struct {
	data []byte
	addr net.Addr
	len  int
}

func newSTUNHandler(conn *net.UDPConn) (*stunHandler, error) {
	// Get the receive buffer size
	fd, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	rcvBufSize, err := syscall.GetsockoptInt(int(fd.Fd()), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return nil, err
	}
	maxPacketAmount := rcvBufSize / 64 // assuming lower bound of per packet metadata of 64 bytes

	return &stunHandler{
		UDPConn:              conn,
		recvChan:             make(chan bufferedPacket, maxPacketAmount),
		queuedBytes:          atomic.Int64{},
		maxQueuedBytes:       int64(rcvBufSize),
		recvStunChan:         make(chan []byte, 100),
		mappings:             make(map[*net.UDPAddr]*natMapping),
		retransmissionTimers: make(map[*net.UDPAddr]*retransmissionTimer),
		writeDeadline:        time.Time{},
	}, nil
}

func (c *stunHandler) queuePacket(pkt bufferedPacket) bool {
	if c.queuedBytes.Load()+int64(len(pkt.data)) > c.maxQueuedBytes {
		return false
	}
	select {
	case c.recvChan <- pkt:
		c.queuedBytes.Add(int64(len(pkt.data)))
		return true
	default:
		return false
	}
}

func (c *stunHandler) dequeuePacket() (bufferedPacket, bool) {
	select {
	case pkt := <-c.recvChan:
		c.queuedBytes.Add(-int64(len(pkt.data)))
		return pkt, true
	default:
		return bufferedPacket{}, false
	}
}

func (c *stunHandler) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		pkt, ok := c.dequeuePacket()
		if ok {
			copy(b, pkt.data)
			return pkt.len, pkt.addr, nil
		}
		n, addr, err := c.UDPConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		if stun.Is(b) {
			c.recvStunChan <- b[:n]
		} else {
			return n, addr, nil
		}
	}
}

func (c *stunHandler) readStunPacket(ctx context.Context) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			select {
			case pkt := <-c.recvStunChan:
				return pkt, nil
			default:
				buf := make([]byte, 1500)
				n, addr, err := c.UDPConn.ReadFrom(buf)
				if err != nil {
					return nil, err
				}
				if stun.Is(buf[:n]) {
					return buf[:n], nil
				} else {
					c.queuePacket(bufferedPacket{data: buf[:n], addr: addr, len: n})
				}
			}
		}
	}
}

type natMapping struct {
	destination *net.UDPAddr
	mappedAddr  *net.UDPAddr
	lastUsed    time.Time
}

func (mapping *natMapping) touch() {
	mapping.lastUsed = time.Now()
}

func (mapping *natMapping) isValid() bool {
	return time.Since(mapping.lastUsed) < timeoutDuration
}

func (c *stunHandler) getMappedAddr(dest *net.UDPAddr) (*net.UDPAddr, error) {
	if mapping, ok := c.mappings[dest]; ok {
		if mapping.isValid() {
			mapping.touch()
			return mapping.mappedAddr, nil
		}
	}

	mapping, err := c.makeStunRequest(dest)
	if err != nil {
		return nil, err
	}
	return mapping.mappedAddr, nil
}

type retransmissionTimer struct {
	// See RFC 6298 for details on these fields
	srtt   time.Duration
	rttvar time.Duration
	rto    time.Duration

	lastUsed time.Time
}

func (c *stunHandler) makeStunRequest(dest *net.UDPAddr) (*natMapping, error) {
	txID := stun.NewTxID()
	stunRequest := stun.Request(txID)

	// Drain STUN channel since we are making a new STUN request
	for len(c.recvStunChan) > 0 {
		<-c.recvStunChan
	}

	if c.retransmissionTimers[dest] == nil {
		c.retransmissionTimers[dest] = &retransmissionTimer{
			srtt:     0,
			rttvar:   0,
			rto:      500 * time.Millisecond, // RFC8489 Section 6.2.1
			lastUsed: time.Now(),
		}
	}

	retransmissionTimer := c.retransmissionTimers[dest]

	// Reset timer if it hasn't been used for 10 minutes (RFC 8489 Section 6.2.1)
	if time.Since(retransmissionTimer.lastUsed) > 10*time.Minute {
		retransmissionTimer.rto = 500 * time.Millisecond
		retransmissionTimer.srtt = 0
		retransmissionTimer.rttvar = 0
	}

	isRetransmission := atomic.Bool{}
	isRetransmission.Store(false)

	var ctx context.Context
	var cancel context.CancelFunc

	if c.writeDeadline.IsZero() {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithDeadline(context.Background(), c.writeDeadline)
	}
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)

	var mappedAddress netip.AddrPort

	// values according to RFC 8489
	// TODO: make configurable?
	const Rc = 7
	const Rm = 16

	var startTime, endTime time.Time

	// Sending goroutine
	g.Go(func() error {
		currentRTO := retransmissionTimer.rto
		startTime = time.Now()
		for i := 0; i < Rc; i++ {
			_, err := c.WriteTo(stunRequest, dest)
			if err != nil {
				return err
			}

			if i == 1 {
				isRetransmission.Store(true)
			}

			var waitDuration time.Duration
			if i < Rc-1 {
				waitDuration = currentRTO
				currentRTO *= 2
			} else {
				waitDuration = Rm * retransmissionTimer.rto
			}

			select {
			case <-time.After(waitDuration):
				// Continue to next iteration or timeout
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return context.DeadlineExceeded
	})

	// Receiving goroutine
	g.Go(func() error {
		for {
			response, err := c.readStunPacket(ctx)
			if err != nil {
				return err
			}
			var responseTxID stun.TxID
			responseTxID, mappedAddress, err = stun.ParseResponse(response)
			if err != nil {
				continue
			}

			if txID == responseTxID {
				endTime = time.Now()
				cancel()
				return nil
			}
		}
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	mappedAddr, err := net.ResolveUDPAddr("udp", mappedAddress.String())
	if err != nil {
		return nil, err
	}
	mapping := c.mappings[dest]
	if mapping == nil {
		mapping = &natMapping{destination: dest}
		c.mappings[dest] = mapping
	}
	mapping.mappedAddr = mappedAddr
	mapping.touch()

	// Skip RTT calculation on retransmission or error
	if isRetransmission.Load() || endTime.IsZero() {
		return mapping, nil
	}

	// Update retransmission timer based on measured RTT, see RFC 6298
	rtt := endTime.Sub(startTime)
	if retransmissionTimer.srtt == 0 {
		retransmissionTimer.srtt = rtt
		retransmissionTimer.rttvar = rtt / 2
	} else {
		srttDiff := retransmissionTimer.srtt - rtt
		if srttDiff < 0 {
			srttDiff = -srttDiff
		}
		retransmissionTimer.rttvar = (3*retransmissionTimer.rttvar + srttDiff) / 4
		retransmissionTimer.srtt = (7*retransmissionTimer.srtt + rtt) / 8
	}
	maxTerm := retransmissionTimer.rttvar * 4
	if maxTerm < time.Millisecond {
		maxTerm = time.Millisecond
	}
	retransmissionTimer.rto = retransmissionTimer.srtt + maxTerm
	retransmissionTimer.lastUsed = time.Now()

	return mapping, nil
}

func (c *stunHandler) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return c.UDPConn.SetWriteDeadline(t)
}
