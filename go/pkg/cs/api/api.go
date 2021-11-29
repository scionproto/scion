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
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/pkg/api"
	cppkiapi "github.com/scionproto/scion/go/pkg/api/cppki/api"
	segapi "github.com/scionproto/scion/go/pkg/api/segments/api"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
)

// Server implements the Control Service API.
type Server struct {
	SegmentsServer segapi.Server
	CPPKIServer    cppkiapi.Server
	CA             renewal.ChainBuilder
	Config         http.HandlerFunc
	Info           http.HandlerFunc
	LogLevel       http.HandlerFunc
	Signer         cstrust.RenewingSigner
	Topology       http.HandlerFunc
}

func (s *Server) GetSegments(w http.ResponseWriter,
	r *http.Request, params GetSegmentsParams) {
	p := segapi.GetSegmentsParams{
		StartIsdAs: (*segapi.IsdAs)(params.StartIsdAs),
		EndIsdAs:   (*segapi.IsdAs)(params.EndIsdAs),
	}
	s.SegmentsServer.GetSegments(w, r, p)
}

func (s *Server) GetSegment(w http.ResponseWriter,
	r *http.Request, ids SegmentIDs) {
	segids := make([]segapi.SegmentID, len(ids))
	for i := range ids {
		segids[i] = segapi.SegmentID(ids[i])
	}
	s.SegmentsServer.GetSegment(w, r, segids)
}

func (s *Server) GetSegmentBlob(w http.ResponseWriter,
	r *http.Request, ids SegmentIDs) {
	segids := make([]segapi.SegmentID, len(ids))
	for i := range ids {
		segids[i] = segapi.SegmentID(ids[i])
	}
	s.SegmentsServer.GetSegmentBlob(w, r, segids)
}

// GetCertificates lists the certificate chains
func (s *Server) GetCertificates(w http.ResponseWriter,
	r *http.Request, params GetCertificatesParams) {
	cppkiParams := cppkiapi.GetCertificatesParams{
		IsdAs:   (*cppkiapi.IsdAs)(params.IsdAs),
		ValidAt: params.ValidAt,
		All:     params.All,
	}
	s.CPPKIServer.GetCertificates(w, r, cppkiParams)
}

// GetCertificate lists the certificate chain for a given ChainID
func (s *Server) GetCertificate(w http.ResponseWriter, r *http.Request, chainID ChainID) {
	s.CPPKIServer.GetCertificate(w, r, cppkiapi.ChainID(chainID))
}

// GetCertificateBlob gnerates a certificate chain blob response encoded as PEM for a given chainId.
func (s *Server) GetCertificateBlob(w http.ResponseWriter, r *http.Request, chainID ChainID) {
	s.CPPKIServer.GetCertificateBlob(w, r, cppkiapi.ChainID(chainID))
}

// GetCa gets the CA info
func (s *Server) GetCa(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.CA.PolicyGen == nil {
		Error(w, Problem{
			Detail: api.StringRef("This instance is not configured with CA capability"),
			Status: http.StatusNotImplemented,
			Title:  "Not a CA",
			Type:   api.StringRef(api.NotImplemented),
		})
		return
	}

	p, err := s.CA.PolicyGen.Generate(r.Context())
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "No active signer",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	ia, err := cppki.ExtractIA(p.Certificate.Subject)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "Unable to extract ISD-AS",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	rep := CA{
		CertValidity: Validity{
			NotAfter:  p.Certificate.NotAfter,
			NotBefore: p.Certificate.NotBefore,
		},
		Policy: Policy{
			ChainLifetime: p.Validity.String(),
		},
		Subject: Subject{
			IsdAs: IsdAs(ia.String()),
		},
		SubjectKeyId: SubjectKeyID(fmt.Sprintf("% X", p.Certificate.SubjectKeyId)),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(rep); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal response",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
}

// GetTrcs gets the trcs specified by it's params.
func (s *Server) GetTrcs(w http.ResponseWriter, r *http.Request, params GetTrcsParams) {
	cppkiParams := cppkiapi.GetTrcsParams{
		Isd: params.Isd,
		All: params.All,
	}
	s.CPPKIServer.GetTrcs(w, r, cppkiParams)
}

// GetTrc gets the trc specified by it's isd base and serial.
func (s *Server) GetTrc(w http.ResponseWriter, r *http.Request, isd int, base int, serial int) {
	s.CPPKIServer.GetTrc(w, r, isd, base, serial)
}

// GetTrcBlob gets the trc encoded pem blob.
func (s *Server) GetTrcBlob(w http.ResponseWriter, r *http.Request, isd int, base int, serial int) {
	s.CPPKIServer.GetTrcBlob(w, r, isd, base, serial)
}

// GetConfig is an indirection to the http handler.
func (s *Server) GetConfig(w http.ResponseWriter, r *http.Request) {
	s.Config(w, r)
}

// GetInfo is an indirection to the http handler.
func (s *Server) GetInfo(w http.ResponseWriter, r *http.Request) {
	s.Info(w, r)
}

// GetLogLevel is an indirection to the http handler.
func (s *Server) GetLogLevel(w http.ResponseWriter, r *http.Request) {
	s.LogLevel(w, r)
}

// SetLogLevel is an indirection to the http handler.
func (s *Server) SetLogLevel(w http.ResponseWriter, r *http.Request) {
	s.LogLevel(w, r)
}

// GetSigner generates the singer response content.
func (s *Server) GetSigner(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	p, err := s.Signer.SignerGen.Generate(r.Context())
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "Unable to get signer",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	rep := Signer{
		AsCertificate: Certificate{
			DistinguishedName: p.Subject.String(),
			IsdAs:             IsdAs(p.IA.String()),
			SubjectKeyAlgo:    p.Algorithm.String(),
			SubjectKeyId:      SubjectKeyID(fmt.Sprintf("% X", p.SubjectKeyID)),
			Validity: Validity{
				NotAfter:  p.ChainValidity.NotAfter,
				NotBefore: p.ChainValidity.NotBefore,
			},
		},
		Expiration: p.Expiration,
		TrcId: TRCID{
			BaseNumber:   int(p.TRCID.Base),
			Isd:          int(p.TRCID.ISD),
			SerialNumber: int(p.TRCID.Serial),
		},
		TrcInGracePeriod: p.InGrace,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(rep); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal response",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
}

// GetSignerChain generates a certificate chain blob response encoded as PEM.
func (s *Server) GetSignerChain(w http.ResponseWriter, r *http.Request) {
	p, err := s.Signer.SignerGen.Generate(r.Context())
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to get signer",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	var buf bytes.Buffer
	if len(p.Chain) == 0 {
		Error(w, Problem{
			Status: http.StatusInternalServerError,
			Title:  "no certificates available",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	for _, cert := range p.Chain {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			Error(w, Problem{
				Detail: api.StringRef(err.Error()),
				Status: http.StatusInternalServerError,
				Title:  "unable to marshal response",
				Type:   api.StringRef(api.InternalError),
			})
			return
		}
	}
	io.Copy(w, &buf)
}

// GetTopology is an indirection to the http handler.
func (s *Server) GetTopology(w http.ResponseWriter, r *http.Request) {
	s.Topology(w, r)
}

// Error creates an detailed error response.
func Error(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	// no point in catching error here, there is nothing we can do about it anymore.
	enc.Encode(p)
}

func (s *Server) GetHealth(w http.ResponseWriter, r *http.Request) {

}
