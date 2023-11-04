package connect

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
)

type Dialer = func(net.Addr, ...squic.EarlyDialerOption) squic.EarlyDialer

func BaseUrl(server net.Addr) string {
	switch s := server.(type) {
	case *snet.UDPAddr:
		host := fmt.Sprintf("%s,%s", s.IA, s.Host.IP)
		return "https://" + net.JoinHostPort(host, strconv.Itoa(s.Host.Port))
	case *snet.SVCAddr:
		return fmt.Sprintf("https://[%s,%s]", s.IA, s.SVC.BaseString())
	default:
		return "https://" + server.String()
	}
}

type HTTPClient struct {
	RoundTripper *http3.RoundTripper
}

func (c HTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.RoundTripper.RoundTrip(req)
}

// AdaptTLS adapts the TLS config to indicate HTTP/3 and connectgrpc support.
func AdaptTLS(cfg *tls.Config) *tls.Config {
	c := cfg.Clone()
	c.NextProtos = []string{"h3", "SCION"}
	return c
}
