package base

import (
	"net"

	log "github.com/inconshreveable/log15"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func DataPlaneWorker(info *ASInfo) {
	log.Debug("Started data plane worker", "AS", info.Name)
	packet := make([]byte, 2000)
	for {
		n, err := info.Device.Read(packet)
		if err != nil {
			log.Error("", "err", err)
			return
		}

		// We already know the destination so no parsing is necessary
		// We encapsulate the packet and send it
		_, err = info.sigs[0].Conn.Write(packet[:n])
		if err != nil {
			log.Error("", "err", err)
			return
		}
	}
}

func DataPlaneReceiver() {
	// Listen for data on port 10080
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: 10080}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Error("", "err", err)
		return
	}

	name := "scion.local"
	// Put decapsulated packets on a tunnel wire
	iface, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: name}})
	if err != nil {
		log.Error("", "err", err)
		return
	}
	log.Debug("Created tun interface", "name", iface.Name())

	link, err := netlink.LinkByName(name)
	if err != nil {
		log.Error("", "err", err)
		return
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		log.Error("", "err", err)
		return
	}

	packet := make([]byte, 2000)
	for {
		n, err := conn.Read(packet)
		if err != nil {
			log.Error("", "err", err)
			return
		}

		//ipP := gopacket.NewPacket(packet[:n], layers.LayerTypeIPv4, gopacket.Default)
		//log.Debug("Parsed packet", "packet", ipP)
		n, err = iface.Write(packet[:n])
		if err != nil {
			log.Error("", "err", err)
			return
		}
	}
}
