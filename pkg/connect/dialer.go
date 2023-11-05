package conect

import (
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/snet"
)

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
