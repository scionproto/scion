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

package cs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/pelletier/go-toml"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
)

// InitTracer initializes the global tracer.
func InitTracer(tracing env.Tracing, id string) (io.Closer, error) {
	tracer, trCloser, err := tracing.NewTracer(id)
	if err != nil {
		return nil, err
	}
	opentracing.SetGlobalTracer(tracer)
	return trCloser, nil
}

// StartHTTPEndpoints starts the HTTP endpoints that expose the metrics and
// additional information.
func StartHTTPEndpoints(cfg interface{}, signer cstrust.RenewingSigner, ca cstrust.ChainBuilder,
	metrics env.Metrics) {

	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		var buf bytes.Buffer
		toml.NewEncoder(&buf).Order(toml.OrderPreserve).Encode(cfg)
		fmt.Fprint(w, buf.String())
	})
	http.HandleFunc("/info", env.InfoHandler)
	http.HandleFunc("/topology", itopo.TopologyHandler)
	http.HandleFunc("/signer", signerHandler(signer))
	if ca != (cstrust.ChainBuilder{}) {
		http.HandleFunc("/ca", caHandler(ca))
	}
	metrics.StartPrometheus()
}

func signerHandler(signer cstrust.RenewingSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s, err := signer.SignerGen.Generate(r.Context())
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
}

func caHandler(signer cstrust.ChainBuilder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s, err := signer.PolicyGen.Generate(r.Context())
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
}
