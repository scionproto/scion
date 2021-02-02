// Copyright 2020 Anapaya Systems
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

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
)

// Server implements the Control Service API.
type Server struct {
	CA       cstrust.ChainBuilder
	Config   http.HandlerFunc
	Info     http.HandlerFunc
	LogLevel http.HandlerFunc
	Signer   cstrust.RenewingSigner
	Topology http.HandlerFunc
}

// GetCa gets the CA info
func (S *Server) GetCa(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s, err := S.CA.PolicyGen.Generate(r.Context())
	if err != nil {
		http.Error(w, "No active signer", http.StatusInternalServerError)
		return
	}

	ia, err := cppki.ExtractIA(s.Certificate.Subject)
	if err != nil || ia == nil {
		http.Error(w, "Unable to get extract ISD-AS", http.StatusInternalServerError)
		return
	}

	type Subject struct {
		IA addr.IA `json:"isd_as"`
	}
	type Validity struct {
		NotBefore time.Time `json:"not_before"`
		NotAfter  time.Time `json:"not_after"`
	}
	type Policy struct {
		ChainLifetime string `json:"chain_lifetime"`
	}
	rep := struct {
		Subject      Subject  `json:"subject"`
		SubjectKeyID string   `json:"subject_key_id"`
		Policy       Policy   `json:"policy"`
		CertValidity Validity `json:"cert_validity"`
	}{
		Subject:      Subject{IA: *ia},
		SubjectKeyID: fmt.Sprintf("% X", s.Certificate.SubjectKeyId),
		Policy: Policy{
			ChainLifetime: fmt.Sprintf("%s", s.Validity),
		},
		CertValidity: Validity{
			NotBefore: s.Certificate.NotBefore,
			NotAfter:  s.Certificate.NotAfter,
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(rep); err != nil {
		http.Error(w, "Unable to marshal response", http.StatusInternalServerError)
		return
	}
}

// GetConfig is an indirection to the http handler.
func (S *Server) GetConfig(w http.ResponseWriter, r *http.Request) {
	S.Config(w, r)
}

// GetInfo is an indirection to the http handler.
func (S *Server) GetInfo(w http.ResponseWriter, r *http.Request) {
	S.Info(w, r)
}

// GetLogLevel is an indirection to the http handler.
func (S *Server) GetLogLevel(w http.ResponseWriter, r *http.Request) {
	S.LogLevel(w, r)
}

// SetLogLevel is an indirection to the http handler.
func (S *Server) SetLogLevel(w http.ResponseWriter, r *http.Request) {
	S.LogLevel(w, r)
}

// GetSigner  generates the singer response content.
func (S *Server) GetSigner(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s, err := S.Signer.SignerGen.Generate(r.Context())
	if err != nil {
		http.Error(w, "Unable to get signer", http.StatusInternalServerError)
		return
	}

	type Subject struct {
		IA addr.IA `json:"isd_as"`
	}
	type TRCID struct {
		ISD    addr.ISD        `json:"isd"`
		Base   scrypto.Version `json:"base_number"`
		Serial scrypto.Version `json:"serial_number"`
	}
	type Validity struct {
		NotBefore time.Time `json:"not_before"`
		NotAfter  time.Time `json:"not_after"`
	}
	rep := struct {
		Subject       Subject   `json:"subject"`
		SubjectKeyID  string    `json:"subject_key_id"`
		Expiration    time.Time `json:"expiration"`
		TRCID         TRCID     `json:"trc_id"`
		ChainValidity Validity  `json:"chain_validity"`
		InGrace       bool      `json:"in_grace_period"`
	}{
		Subject:      Subject{IA: s.IA},
		SubjectKeyID: fmt.Sprintf("% X", s.SubjectKeyID),
		Expiration:   s.Expiration,
		TRCID: TRCID{
			ISD:    s.TRCID.ISD,
			Base:   s.TRCID.Base,
			Serial: s.TRCID.Serial,
		},
		ChainValidity: Validity{
			NotBefore: s.ChainValidity.NotBefore,
			NotAfter:  s.ChainValidity.NotAfter,
		},
		InGrace: s.InGrace,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(rep); err != nil {
		http.Error(w, "Unable to marshal response", http.StatusInternalServerError)
		return
	}
}

// GetTopology is an indirection to the http handler.
func (S *Server) GetTopology(w http.ResponseWriter, r *http.Request) {
	S.Topology(w, r)
}
