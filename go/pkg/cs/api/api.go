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
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	api "github.com/scionproto/scion/go/pkg/api"
	cppkiapi "github.com/scionproto/scion/go/pkg/api/cppki/api"
	healthapi "github.com/scionproto/scion/go/pkg/api/health/api"
	segapi "github.com/scionproto/scion/go/pkg/api/segments/api"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	"github.com/scionproto/scion/go/pkg/storage"
	beaconstorage "github.com/scionproto/scion/go/pkg/storage/beacon"
)

type BeaconStore interface {
	GetBeacons(context.Context, *beaconstorage.QueryParams) ([]beaconstorage.Beacon, error)
}

type Healther interface {
	GetSignerHealth(context.Context) SignerHealthData
	GetTRCHealth(context.Context) TRCHealthData
}

// SignerHealthData is used to extract the relevant signer data for the signer health check.
type SignerHealthData struct {
	SignerMissing       bool
	SignerMissingDetail string
	Expiration          time.Time
	InGrace             bool
}

// TRCHealthData is used to extract the relevant TRC data for the TRC health check.
type TRCHealthData struct {
	TRCNotFound       bool
	TRCNotFoundDetail string
	TRCID             cppki.TRCID
}

// Server implements the Control Service API.
type Server struct {
	SegmentsServer segapi.Server
	CPPKIServer    cppkiapi.Server
	Beacons        BeaconStore
	CA             renewal.ChainBuilder
	Config         http.HandlerFunc
	Info           http.HandlerFunc
	LogLevel       http.HandlerFunc
	Signer         cstrust.RenewingSigner
	Topology       http.HandlerFunc
	TrustDB        storage.TrustDB
	Healther       Healther
}

// UnpackBeaconUsages extracts the Usage's bits as snake case string constants for the API.
func UnpackBeaconUsages(u beacon.Usage) []string {
	var names []string
	if u&beacon.UsageUpReg != 0 {
		names = append(names, string(BeaconUsageUpRegistration))
	}
	if u&beacon.UsageDownReg != 0 {
		names = append(names, string(BeaconUsageDownRegistration))
	}
	if u&beacon.UsageCoreReg != 0 {
		names = append(names, string(BeaconUsageCoreRegistration))
	}
	if u&beacon.UsageProp != 0 {
		names = append(names, string(BeaconUsagePropagation))
	}
	return names
}

// GetBeacons gets the stored in the BeaconDB.
func (s *Server) GetBeacons(w http.ResponseWriter, r *http.Request, params GetBeaconsParams) {
	q := beaconstorage.QueryParams{}
	var errs serrors.List
	if params.StartIsdAs != nil {
		if ia, err := addr.IAFromString(string(*params.StartIsdAs)); err == nil {
			q.StartsAt = []addr.IA{ia}
		} else {
			errs = append(errs, serrors.WrapStr("parsing start_isd_as", err))
		}
	}
	if params.Usages != nil {
		var usage beacon.Usage
		for _, usageFlag := range *params.Usages {
			switch usageFlag {
			case BeaconUsageCoreRegistration:
				usage |= beacon.UsageCoreReg
			case BeaconUsageDownRegistration:
				usage |= beacon.UsageDownReg
			case BeaconUsagePropagation:
				usage |= beacon.UsageProp
			case BeaconUsageUpRegistration:
				usage |= beacon.UsageUpReg
			default:
				errs = append(errs, serrors.New(
					"unknown value for parameter",
					"usage",
					usageFlag,
				))
			}
		}
		q.Usages = []beacon.Usage{usage}
	}

	if params.IngressInterface != nil {
		if *params.IngressInterface < 0 || *params.IngressInterface > 65535 {
			errs = append(errs, serrors.New(
				"value for parameter out of range",
				"ingress_interface",
				*params.IngressInterface,
			))
		}
		q.IngressInterfaces = []uint16{uint16(*params.IngressInterface)}
	}
	switch {
	case (params.All != nil) && *params.All:
		q.ValidAt = time.Time{}
	case params.ValidAt != nil:
		q.ValidAt = *params.ValidAt
	default:
		q.ValidAt = time.Now()
	}
	sortFn, err := sortFactory(params.Sort)
	if err != nil {
		errs = append(errs, err)
	}

	if err := errs.ToError(); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusBadRequest,
			Title:  "malformed query parameters",
			Type:   api.StringRef(api.BadRequest),
		})
		return
	}
	results, err := s.Beacons.GetBeacons(r.Context(), &q)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting beacons",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}

	rep := make([]*Beacon, 0, len(results))
	for _, result := range results {
		s := result.Beacon.Segment
		var usage BeaconUsages
		for _, name := range UnpackBeaconUsages(result.Usage) {
			usage = append(usage, BeaconUsage(name))
		}
		var hops []Hop
		for i, as := range s.ASEntries {
			if i != 0 {
				hops = append(hops, Hop{
					Interface: int(as.HopEntry.HopField.ConsIngress),
					IsdAs:     IsdAs(as.Local.String())})
			}
			if i != len(s.ASEntries)-1 {
				hops = append(hops, Hop{
					Interface: int(as.HopEntry.HopField.ConsEgress),
					IsdAs:     IsdAs(as.Local.String())})
			}
		}
		rep = append(rep, &Beacon{
			Usages:           usage,
			IngressInterface: int(result.Beacon.InIfId),
			Segment: Segment{
				Id:          SegmentID(segapi.SegID(s)),
				LastUpdated: result.LastUpdated,
				Timestamp:   s.Info.Timestamp.UTC(),
				Expiration:  s.MinExpiry().UTC(),
				Hops:        hops,
			},
		})
	}
	// Sort the results.
	sortFn(rep)
	if params.Desc != nil && *params.Desc {
		// reverse rep.
		for i, j := 0, len(rep)-1; i < j; i, j = i+1, j-1 {
			rep[i], rep[j] = rep[j], rep[i]
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(map[string][]*Beacon{"beacons": rep}); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal response",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
}

func sortFactory(sortParam *GetBeaconsParamsSort) (func(b []*Beacon), error) {
	by := "last_updated"
	if sortParam != nil {
		by = string(*sortParam)
	}
	switch by {
	case "expiration_time":
		return func(b []*Beacon) {
			sort.Slice(b, func(i, j int) bool {
				return b[i].Segment.Expiration.Before(b[j].Segment.Expiration)
			})
		}, nil
	case "info_time":
		return func(b []*Beacon) {
			sort.Slice(b, func(i, j int) bool {
				return b[i].Segment.Timestamp.Before(b[j].Segment.Timestamp)
			})
		}, nil
	case "start_isd_as":
		return func(b []*Beacon) {
			sort.Slice(b, func(i, j int) bool {
				if len(b[i].Segment.Hops) == 0 || len(b[j].Segment.Hops) == 0 {
					return len(b[i].Segment.Hops) < len(b[j].Segment.Hops)
				}
				return b[i].Segment.Hops[0].IsdAs < b[j].Segment.Hops[0].IsdAs
			})
		}, nil
	case "last_updated":
		return func(b []*Beacon) {
			sort.Slice(b, func(i, j int) bool { return b[i].LastUpdated.Before(b[j].LastUpdated) })
		}, nil
	case "ingress_interface_id":
		return func(b []*Beacon) {
			sort.Slice(b, func(i, j int) bool {
				return b[i].IngressInterface < b[j].IngressInterface
			})
		}, nil
	default:
		return nil, serrors.New("unknown query parameter", "sort", by)
	}
}

// GetSegments gets the stored in the PathDB.
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

// GetCertificates lists the certificate chains.
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

func (s *Server) GetHealth(w http.ResponseWriter, r *http.Request) {
	signerHealth := s.Healther.GetSignerHealth(r.Context())
	signerCheck := Check{
		Status: StatusPassing,
		Name:   "valid signer available",
	}
	switch {
	case signerHealth.SignerMissing:
		signerCheck.Status = StatusFailing
		if signerHealth.SignerMissingDetail != "" {
			signerCheck.Detail = api.StringRef(signerHealth.SignerMissingDetail)
		}
	case time.Until(signerHealth.Expiration) <= 0:
		signerCheck.Status = StatusFailing
		signerCheck.Detail = api.StringRef("signer certificate has expired")
		signerCheck.Data = CheckData{
			AdditionalProperties: map[string]interface{}{
				"expires_at": signerHealth.Expiration.Format(time.RFC3339),
			},
		}
	case signerHealth.InGrace:
		signerCheck.Status = StatusDegraded
		signerCheck.Data = CheckData{
			AdditionalProperties: map[string]interface{}{
				"expires_at": signerHealth.Expiration.Format(time.RFC3339),
				"in_grace":   true,
			},
		}
		signerCheck.Detail = api.StringRef(`signer certificate is authenticated
		by TRC in grace period`)
	case time.Until(signerHealth.Expiration) < 6*time.Hour:
		signerCheck.Status = StatusDegraded
		signerCheck.Data = CheckData{
			AdditionalProperties: map[string]interface{}{
				"expires_at": signerHealth.Expiration.Format(time.RFC3339),
			},
		}
		signerCheck.Detail = api.StringRef("signer certificate is close to expiration")
	default:
		signerCheck.Data = CheckData{
			AdditionalProperties: map[string]interface{}{
				"expires_at": signerHealth.Expiration.Format(time.RFC3339),
			},
		}
	}

	trcCheck := Check{
		Status: StatusFailing,
		Name:   "TRC for local ISD available",
	}
	trcHealthData := s.Healther.GetTRCHealth(r.Context())
	if trcHealthData.TRCNotFoundDetail != "" {
		trcCheck.Detail = api.StringRef(trcHealthData.TRCNotFoundDetail)
	}
	if !trcHealthData.TRCNotFound {
		trcCheck.Status = StatusPassing
		trcCheck.Data = CheckData{
			AdditionalProperties: map[string]interface{}{
				"base_number":   trcHealthData.TRCID.Base,
				"serial_number": trcHealthData.TRCID.Serial,
				"isd":           trcHealthData.TRCID.ISD,
			},
		}
	}

	rep := HealthResponse{
		Health: Health{
			Status: Status(healthapi.AggregateHealthStatus(
				[]healthapi.Status{healthapi.Status(signerCheck.Status),
					healthapi.Status(trcCheck.Status)})),
			Checks: []Check{
				signerCheck,
				trcCheck,
			},
		},
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

// Error creates an detailed error response.
func Error(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	// no point in catching error here, there is nothing we can do about it anymore.
	enc.Encode(p)
}
