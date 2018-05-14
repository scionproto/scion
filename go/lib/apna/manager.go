package main

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

// Session details
type Session struct {
	pubkey int
}

// CreateSession create a new APNA session
func CreateSession() (session *Session) {
	return &Session{}
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
	defer serverConn.Close()
	buf := make([]byte, 2048)
	for {
		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			log.WithField("err", err).Error("Read Failed")
		}
		log.WithFields(log.Fields{
			"data": string(buf[0:n]),
			"addr": addr,
		}).Debug("Received information")
	}
}
