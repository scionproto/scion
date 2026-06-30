// Copyright 2026 Anapaya Systems
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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

// alpn is the HTTP/3 ALPN protocol identifier.
const alpn = "h3"

// ignoreSCMP is an SCMP handler that swallows all SCMP messages. Both the QUIC
// server and client must not surface SCMP errors from their read loop,
// otherwise the connection enters a broken state.
type ignoreSCMP struct{}

func (ignoreSCMP) Handle(*snet.Packet) error { return nil }

// dialDaemon connects to the SCION daemon at the given address and loads the
// local topology.
func dialDaemon(ctx context.Context, sciond string) (daemon.Connector, snet.Topology, error) {
	conn, err := daemon.NewAutoConnector(ctx, daemon.WithDaemon(sciond))
	if err != nil {
		return nil, snet.Topology{}, serrors.Wrap("connecting to SCION daemon", err)
	}
	topo, err := daemon.LoadTopology(ctx, conn)
	if err != nil {
		return nil, snet.Topology{}, serrors.Wrap("loading topology", err)
	}
	return conn, topo, nil
}

// quicConfig returns a QUIC configuration tuned for SCION: the initial packet
// size and path-MTU discovery are kept conservative so QUIC packets, once
// wrapped in a SCION header, stay within the smallest SCION path MTU (1280).
func quicConfig() *quic.Config {
	return &quic.Config{
		InitialPacketSize:       1000,
		DisablePathMTUDiscovery: true,
		MaxIdleTimeout:          30 * time.Second,
	}
}

// selfSignedCert generates an ephemeral self-signed certificate for the server.
// The client uses InsecureSkipVerify, so the contents are irrelevant beyond
// being a valid certificate with the h3 ALPN.
func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, serrors.Wrap("generating key", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "e2e-http"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"e2e-http"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, serrors.Wrap("creating certificate", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
