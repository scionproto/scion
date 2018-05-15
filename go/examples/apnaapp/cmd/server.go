package cmd

import (
	"fmt"
	"log"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

var apnaManagerPort = 3001

func getDefaultSCIONDPath(ia addr.IA) string {
	return fmt.Sprintf("/run/shm/sciond/sd%s.sock", ia.FileFmt(false))
}

func getDefaultDispatcherSock() string {
	return "/run/shm/dispatcher/default.sock"
}

func connectToApnaManager() *net.UDPConn {
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", apnaManagerPort))
	if err != nil {
		panic(err)
	}
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		panic(err)
	}
	return conn
}

func StartServer(server *snet.Addr) {
	// Initialize default SCION networking context
	sciond := getDefaultSCIONDPath(server.IA)
	dispatcher := getDefaultDispatcherSock()
	if err := snet.Init(server.IA, sciond, dispatcher); err != nil {
		log.Fatal("Unable to initialize SCION network", "err", err)
	}
	log.Print("SCION Network successfully initialized")

	// Connect to management service
	conn := connectToApnaManager()
	msg := []byte{1}
	conn.Write(msg)

	sconn, err := snet.ListenSCION("udp4", server)
	if err != nil {
		panic(err)
	}
	for /* ever */ {
		handleConnection(sconn)
	}
}

func handleConnection(conn *snet.Conn) {
	buf := make([]byte, 1024)
	n, raddr, err := conn.ReadFromSCION(buf)
	if err != nil {
		panic(err)
	}
	log.Print("Data Received: ", buf[:n])
	n, err = conn.WriteToSCION([]byte("Bye!"), raddr)
	if err != nil {
		panic(err)
	}
	log.Print("Reply Sent of size: ", n)
}
