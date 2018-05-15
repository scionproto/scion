package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/dchest/siphash"
	log "github.com/sirupsen/logrus"
)

type hostID = net.IP

var epoch = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

const (
	key1 = uint64(0xdeadbeef)
	key2 = uint64(0xcafebabe)
)

// Session details
type Session struct {
	pubkey int
}

type EphID struct {
	host      [3]byte
	timestamp [4]byte
	kind      [1]byte
}

// CreateSession create a new APNA session
func CreateSession() (session *Session) {
	return &Session{}
}

func getExpTime(kind int) []byte {
	currTime := time.Now()
	switch kind {
	case 0:
		currTime.Add(time.Minute * 5)
	case 1:
		currTime.Add(time.Hour)
	}
	timestamp := (currTime.Unix() - epoch) / 60
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(timestamp))
	return bs
}

func generateHostID(host hostID) []byte {
	uid := siphash.Hash(key1, key2, host)
	bs := make([]byte, 8)
	binary.LittleEndian.PutUint64(bs, uid)
	return bs
}

const (
	maxThreads = 4
)

func handleRequest(buf []byte, addr *net.UDPAddr) (ephID *EphID) {
	ephID = &EphID{}
	copy(ephID.host[:], generateHostID(addr.IP)[:3])

	switch buf[0] {
	case 0x00:
		ephID.kind[0] = 0
		copy(ephID.timestamp[:], getExpTime(0))
	case 0x01:
		ephID.kind[0] = 1
		copy(ephID.timestamp[:], getExpTime(1))
	}
	return
}

func handleConnection(serverConn *net.UDPConn, quit chan struct{}) {
	for {
		buf := make([]byte, 2048)
		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			log.WithField("err", err).Error("Read Failed")
			quit <- struct{}{}
		} else {
			log.WithFields(log.Fields{
				"data": string(buf[0:n]),
				"addr": addr,
			}).Info("Received information")
			log.WithFields(log.Fields{
				"ephId": handleRequest(buf, addr),
			}).Info("EphID Generation")
		}
	}
}

// RunServer runs apna session manager
func RunServer(port int) error {
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", port))
	if err != nil {
		return err
	}
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		return err
	}
	log.Infof("Started apna session manager on port %v", port)
	quit := make(chan struct{})
	for i := 0; i < maxThreads; i++ {
		go handleConnection(serverConn, quit)
	}
	<-quit
	return nil
}
