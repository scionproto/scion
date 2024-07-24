// Copyright 2021 Anapaya Systems
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

package mgmtapi

import (
	"net/http"

	cppkiapi "github.com/scionproto/scion/private/mgmtapi/cppki/api"
	segapi "github.com/scionproto/scion/private/mgmtapi/segments/api"
)

// Server implements the SCION Daemon Service API.
type Server struct {
	SegmentsServer segapi.Server
	CPPKIServer    cppkiapi.Server
	Config         http.HandlerFunc
	Info           http.HandlerFunc
	LogLevel       http.HandlerFunc
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

// GetSegments reads the known segments from the pathdb and returns them encoded as json.
func (s *Server) GetSegments(
	w http.ResponseWriter,
	r *http.Request,
	params GetSegmentsParams,
) {

	p := segapi.GetSegmentsParams{
		StartIsdAs: params.StartIsdAs,
		EndIsdAs:   params.EndIsdAs,
	}
	s.SegmentsServer.GetSegments(w, r, p)
}

func (s *Server) GetSegment(w http.ResponseWriter, r *http.Request, id SegmentID) {
	s.SegmentsServer.GetSegment(w, r, id)
}

func (s *Server) DeleteSegment(w http.ResponseWriter, r *http.Request, id SegmentID) {
	s.SegmentsServer.DeleteSegment(w, r, id)
}

func (s *Server) GetSegmentBlob(w http.ResponseWriter, r *http.Request, id SegmentID) {
	s.SegmentsServer.GetSegmentBlob(w, r, id)
}

// GetCertificates lists the certificate chains.
func (s *Server) GetCertificates(
	w http.ResponseWriter,
	r *http.Request,
	params GetCertificatesParams,
) {

	cppkiParams := cppkiapi.GetCertificatesParams{
		IsdAs:   params.IsdAs,
		ValidAt: params.ValidAt,
		All:     params.All,
	}
	s.CPPKIServer.GetCertificates(w, r, cppkiParams)
}

// GetCertificate lists the certificate chain for a given ChainID.
func (s *Server) GetCertificate(w http.ResponseWriter, r *http.Request, chainID ChainID) {
	s.CPPKIServer.GetCertificate(w, r, chainID)
}

// GetCertificateBlob gnerates a certificate chain blob response encoded as PEM for a given chainId.
func (s *Server) GetCertificateBlob(w http.ResponseWriter, r *http.Request, chainID ChainID) {
	s.CPPKIServer.GetCertificateBlob(w, r, chainID)
}

// GetTrcs gets the trcs specified by it's params.
func (s *Server) GetTrcs(
	w http.ResponseWriter,
	r *http.Request,
	params GetTrcsParams, // nolint - name from published API
) {
	cppkiParams := cppkiapi.GetTrcsParams{ // nolint - name from published API
		Isd: params.Isd,
		All: params.All,
	}
	s.CPPKIServer.GetTrcs(w, r, cppkiParams) // nolint - name from published API
}

// GetTrc gets the trc specified by it's isd base and serial.
func (s *Server) GetTrc(w http.ResponseWriter, r *http.Request, isd int, base int, serial int) {
	s.CPPKIServer.GetTrc(w, r, isd, base, serial) // nolint - name from published API
}

// GetTrcBlob gets the trc encoded pem blob.
func (s *Server) GetTrcBlob(w http.ResponseWriter, r *http.Request, isd int, base int, serial int) {
	s.CPPKIServer.GetTrcBlob(w, r, isd, base, serial) // nolint - name from published API
}
