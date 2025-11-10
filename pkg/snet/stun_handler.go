package snet

import (
	"github.com/scionproto/scion/pkg/stun"
	"net"
	"time"
)

const timeoutDuration = 5 * time.Minute

// stunHandler is a wrapper around net.UDPConn that handles STUN requests.
type stunHandler struct {
	*net.UDPConn
	recvChan     chan bufferedPacket
	recvStunChan chan []byte
	mappings     map[*net.UDPAddr]*natMapping // TODO: necessary to protect with mutex?
}

type bufferedPacket struct {
	data []byte
	addr net.Addr
	len  int
}

func newSTUNHandler(conn *net.UDPConn) *stunHandler {
	return &stunHandler{
		UDPConn:      conn,
		recvChan:     make(chan bufferedPacket, 100),
		recvStunChan: make(chan []byte, 100),
		mappings:     make(map[*net.UDPAddr]*natMapping),
	}
}

func (c *stunHandler) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case pkt := <-c.recvChan:
			b = pkt.data
			return pkt.len, pkt.addr, nil
		default:
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
}

func (c *stunHandler) readStunPacket() ([]byte, error) {
	select {
	case pkt := <-c.recvStunChan:
		return pkt, nil
	default:
		for {
			buf := make([]byte, 1500)
			n, addr, err := c.UDPConn.ReadFrom(buf)
			if err != nil {
				return nil, err
			}
			if stun.Is(buf[:n]) {
				return buf[:n], nil
			} else {
				c.recvChan <- bufferedPacket{data: buf[:n], addr: addr, len: n}
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

// TODO: handle resending requests on timeout
func (c *stunHandler) makeStunRequest(dest *net.UDPAddr) (*natMapping, error) {
	txID := stun.NewTxID()
	stunRequest := stun.Request(txID)
	_, err := c.WriteTo(stunRequest, dest)
	if err != nil {
		return nil, err
	}

	for {
		response, err := c.readStunPacket()
		if err != nil {
			return nil, err
		}
		responseTxID, mappedAddress, err := stun.ParseResponse(response)
		if err != nil {
			continue
		}

		if txID != responseTxID {
			continue
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

		return mapping, nil
	}
}
