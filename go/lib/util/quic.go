// Copyright 2018 Anapaya Systems
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

package util

import (
	"crypto/tls"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	quicDefKeyFile  = "gen-certs/tls.key"
	quicDefCertFile = "gen-certs/tls.pem"
)

// CreateTLSConfig creates a TLS config for quic.
// TODO(lukedirtwalker): This should go in squic package
// but currently that leads to an import cycle since it is used in quic_transport as well.
func CreateTLSConfig(tlsCertFile, tlsKeyFile string) (*tls.Config, error) {
	if tlsCertFile == "" {
		tlsCertFile = quicDefCertFile
	}
	if tlsKeyFile == "" {
		tlsKeyFile = quicDefKeyFile
	}
	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		return nil, common.NewBasicError("quic: Unable to load TLS cert/key", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
