// Copyright 2025 SCION Association, Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connect

import (
	"crypto/tls"
	"net"
	"net/http"
	"strconv"

	"github.com/quic-go/quic-go/http3"

	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
)

type Dialer = func(net.Addr, ...squic.EarlyDialerOption) squic.EarlyDialer

// BaseUrl constructs a URL suitable for connectrpc/HTTP3 requests.
// The URL only needs to be syntactically valid; actual SCION routing is handled by
// the pre-configured QUIC dialer which ignores the URL authority.
// Full SCION addresses (e.g. "1-ff00:0:110,127.0.0.1:31000") contain colons that are
// not valid in URL host components, so we extract just the underlay IP:port for
// UDP addresses and use a synthetic hostname for SVC addresses.
func BaseUrl(server net.Addr) string {
	switch s := server.(type) {
	case *snet.UDPAddr:
		host := net.JoinHostPort(s.Host.IP.String(), strconv.Itoa(s.Host.Port))
		return "https://" + host
	case *snet.SVCAddr:
		return "https://" + s.SVC.BaseString() + ".scion:443"
	}
	return "https://" + server.String()
}

type HTTPClient struct {
	RoundTripper *http3.Transport
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

// AdaptClientTLS adapts the TLS config for use with a client, specifically
// setting the NextProtos to "h3" to require HTTP/3 support.
func AdaptClientTLS(cfg *tls.Config) *tls.Config {
	c := cfg.Clone()
	c.NextProtos = []string{"h3"}
	return c
}
