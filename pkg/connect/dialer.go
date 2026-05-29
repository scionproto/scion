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
	"strings"

	"github.com/quic-go/quic-go/http3"

	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
)

type Dialer = func(net.Addr, ...squic.EarlyDialerOption) squic.EarlyDialer

// BaseUrl constructs a URL suitable for connectrpc/HTTP3 requests.
// Full SCION addresses (e.g. "1-ff00:0:110,127.0.0.1:31000") are not RFC 3986 compliant.
// We encode the full SCION address into a valid hostname by replacing
// colons with dashes, dots with dashes, and the comma with an underscore:
//
//   - "1-ff00:0:110,10.0.0.1:31000" -> "https://scion4-1-ff00-0-110_10-0-0-1:31000"
//   - "1-ff00:0:110,[::1]:31000"    -> "https://scion6-1-ff00-0-110_--1:31000"
//   - "1-ff00:0:110,CS"             -> "https://scion-1-ff00-0-110_CS"
func BaseUrl(server net.Addr) string {
	switch s := server.(type) {
	case *snet.UDPAddr:
		ia := strings.ReplaceAll(s.IA.String(), ":", "-")
		ip := s.Host.IP.String()
		port := strconv.Itoa(s.Host.Port)
		if s.Host.IP.To4() != nil {
			ip = strings.ReplaceAll(ip, ".", "-")
			return "https://scion4-" + ia + "_" + ip + ":" + port
		}
		ip = strings.ReplaceAll(ip, ":", "-")
		return "https://scion6-" + ia + "_" + ip + ":" + port
	case *snet.SVCAddr:
		ia := strings.ReplaceAll(s.IA.String(), ":", "-")
		return "https://scion-" + ia + "_" + s.SVC.BaseString()
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
