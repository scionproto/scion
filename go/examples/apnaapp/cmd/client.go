package cmd

import (
	"log"

	"github.com/scionproto/scion/go/lib/snet"
)

func StartClient(client *snet.Addr, server *snet.Addr) {
	// Initialize default SCION networking context
	sciond := getDefaultSCIONDPath(client.IA)
	dispatcher := getDefaultDispatcherSock()
	if err := snet.Init(client.IA, sciond, dispatcher); err != nil {
		log.Fatal("Unable to initialize SCION network", "err", err)
	}
	log.Print("SCION Network successfully initialized")
	cconn, err := snet.DialSCION("udp4", client, server)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	n, err := cconn.Write([]byte("Hello!"))
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 1024)
	n, err = cconn.Read(buf)
	for n == 0 {
		n, err = cconn.Read(buf)
	}
	log.Print("Client Recived: ", buf[:n])
}
