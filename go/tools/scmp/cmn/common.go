package cmn

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spkt"
)

const (
	DefaultInterval = 1 * time.Second
	DefaultTimeout  = 2 * time.Second
	MaxEchoes       = 1 << 16
)

type ScmpStats struct {
	// sent is the number of sent packets
	Sent uint
	// recv is the number of received packets
	Recv uint
}

var (
	Interactive bool
	Interval    time.Duration
	Timeout     time.Duration
	Count       uint
	PathEntry   *sciond.PathReplyEntry
	Mtu         uint16
	Local       snet.Addr
	Remote      snet.Addr
	Bind        snet.Addr
	Conn        *reliable.Conn
	rnd         *rand.Rand
	Stats       *ScmpStats
)

func init() {
	flag.BoolVar(&Interactive, "i", false, "Interactive mode")
	flag.DurationVar(&Interval, "interval", DefaultInterval, "time between packets")
	flag.DurationVar(&Timeout, "timeout", DefaultTimeout, "timeout per packet")
	flag.UintVar(&Count, "c", 0, "Total number of packet to send (ignored if not echo)")
	flag.Var((*snet.Addr)(&Local), "local", "(Mandatory) address to listen on")
	flag.Var((*snet.Addr)(&Remote), "remote", "(Mandatory for clients) address to connect to")
	flag.Var((*snet.Addr)(&Bind), "bind", "address to bind to, if running behind NAT")
	flag.Usage = scmpUsage
	seed := rand.NewSource(time.Now().UnixNano())
	rnd = rand.New(seed)
}

func scmpUsage() {
	fmt.Fprintf(os.Stderr, `
Usage: scmp <command> [flags]

command:
   echo
   tr | traceroute
   rp | recordpath

flags:
`)
	flag.PrintDefaults()
}

func ValidateFlags() {
	if Local.Host == nil {
		Fatal("Invalid local address")
	}
	if Remote.Host == nil {
		Fatal("Invalid remote address")
	}
	// scmp-tool does not use ports, thus they should not be set
	// Still, the user could set port as 0 ie, ISD-AS,[host]:0 and be valid
	if Local.L4Port != 0 {
		Fatal("Local port should not be provided")
	}
	if Remote.L4Port != 0 {
		Fatal("Remote port should not be provided")
	}
	if Interval == 0 {
		Interval = 1
	}
}

func NewSCMPPkt(t scmp.Type, info scmp.Info, ext common.Extension) *spkt.ScnPkt {
	var exts []common.Extension
	scmpMeta := scmp.Meta{InfoLen: uint8(info.Len() / common.LineLen)}
	pld := make(common.RawBytes, scmp.MetaLen+info.Len())
	scmpMeta.Write(pld)
	info.Write(pld[scmp.MetaLen:])
	scmpHdr := scmp.NewHdr(scmp.ClassType{Class: scmp.C_General, Type: t}, len(pld))
	if ext != nil {
		exts = []common.Extension{ext}
	}
	pkt := &spkt.ScnPkt{
		DstIA:   Remote.IA,
		SrcIA:   Local.IA,
		DstHost: Remote.Host,
		SrcHost: Local.Host,
		Path:    Remote.Path,
		HBHExt:  exts,
		L4:      scmpHdr,
		Pld:     pld,
	}
	return pkt
}

func NextHopAddr() net.Addr {
	nhAddr := reliable.AppAddr{Addr: Remote.NextHopHost, Port: Remote.NextHopPort}
	if Remote.NextHopHost == nil {
		nhAddr = reliable.AppAddr{Addr: Remote.Host, Port: overlay.EndhostPort}
	}
	return &nhAddr
}

func Rand() uint64 {
	return rnd.Uint64()
}

func UpdatePktTS(pkt *spkt.ScnPkt, ts time.Time) {
	scmpHdr := pkt.L4.(*scmp.Hdr)
	scmpHdr.Timestamp = uint64(ts.UnixNano()) / 1000
}

func Fatal(msg string, a ...interface{}) {
	fmt.Printf("CRIT: "+msg+"\n", a...)
	os.Exit(1)
}
