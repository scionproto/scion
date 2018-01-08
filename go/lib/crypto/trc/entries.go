// Copyright 2017 ETH Zurich
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

package trc

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// CoreAS is the core AS entry.
type CoreAS struct {
	// All fields need to be sorted in alphabetic order of the field names.

	// OfflineKey is the offline verification key.
	OfflineKey common.RawBytes
	// OfflineKeyAlg is the offline key signing algorithm.
	OfflineKeyAlg string
	// OnlineKey is the online verification key.
	OnlineKey common.RawBytes
	// OnlineKeyAlg is the online key singing algorithm.
	OnlineKeyAlg string
}

// RootCA is the root CA entry.
type RootCA struct {
	// All fields need to be sorted in alphabetic order of the field names.

	// ARPKIKey is the arpki key.
	ARPKIKey common.RawBytes
	// ARPKISrv is a list of arpki server addresses.
	ARPKISrv []*Addr
	// Certificate is a public key certificate
	Certificate common.RawBytes
	// OnlineKey is the online verification key.
	OnlineKey common.RawBytes
	// OnlineKeyAlg is the online key signing algorithm.
	OnlineKeyAlg string
	// TRCSrv is a list of servers, which handle TRC signing requests.
	TRCSrv []*Addr
}

// Rains is the rains entry.
type Rains struct {
	// All fields need to be sorted in alphabetic order of the field names.

	// OnlineKey is the online verification key.
	OnlineKey common.RawBytes `json:",omitempty"`
	// OnlineKeyAlg is the online key signing algorithm.
	OnlineKeyAlg string `json:",omitempty"`
	// RootRAINSKey is the root rains key
	RootRAINSKey common.RawBytes `json:",omitempty"`
	// TRCSrv is a list of servers, which handle TRC signing requests.
	TRCSrv []*Addr `json:",omitempty"`
}

// CertLog is the cert log server entry.
type CertLog struct {
	// All fields need to be sorted in alphabetic order of the field names.

	// Addr is the address of the cert log server.
	Addr *Addr
	// Certificate is the public key certificate.
	Certificate common.RawBytes
}

func (c *CertLog) MarshalJSON() ([]byte, error) {
	m := make(map[string]common.RawBytes, 1)
	m[c.Addr.String()] = c.Certificate
	return json.Marshal(m)
}

func (c *CertLog) UnmarshalJSON(b []byte) error {
	var m map[string]common.RawBytes
	err := json.Unmarshal(b, &m)
	if err != nil {
		return err
	}
	if len(m) != 1 {
		return common.NewBasicError("Invalid number of sub-entries in CertLogEntry", nil,
			"expect", 1, "actual", len(m))
	}
	for key, cert := range m {
		c.Addr = &Addr{}
		c.Addr.ParseString(key)
		c.Certificate = cert
	}
	return nil
}

// Addr is the (ISD-AS IP)-tuple used for entity addresses in the TRC file.
type Addr struct {
	// IA is the ISD-AS.
	IA *addr.ISD_AS
	// IP is the IP.
	IP net.IP
}

func (a *Addr) String() string {
	return fmt.Sprintf("%s,%s", a.IA, a.IP)
}

// ParseString parses a string of the format "ISD-AS IP" and sets the struct fields accordingly.
func (a *Addr) ParseString(addr_ string) error {
	l := strings.Split(addr_, ",")
	if len(l) != 2 {
		return common.NewBasicError("Invalid address", nil, "raw", addr_, "err", "wrong format")
	}
	ia, err := addr.IAFromString(l[0])
	if err != nil {
		return common.NewBasicError("Invalid address", err, "raw", addr_)
	}
	ip := net.ParseIP(l[1])
	if ip == nil {
		return common.NewBasicError("Invalid address", nil, "raw", addr_, "err", "Invalid IP")
	}
	a.IA = ia
	a.IP = ip
	return nil
}

func (a *Addr) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%s", a))
}

func (a *Addr) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return a.ParseString(s)
}
