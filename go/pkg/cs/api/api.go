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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/api"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	"github.com/scionproto/scion/go/pkg/storage"
	truststorage "github.com/scionproto/scion/go/pkg/storage/trust"
	"github.com/scionproto/scion/go/pkg/trust"
)

type SegmentsStore interface {
	Get(context.Context, *query.Params) (query.Results, error)
}

// Server implements the Control Service API.
type Server struct {
	Segments SegmentsStore
	CA       renewal.ChainBuilder
	Config   http.HandlerFunc
	Info     http.HandlerFunc
	LogLevel http.HandlerFunc
	Signer   cstrust.RenewingSigner
	Topology http.HandlerFunc
	TrustDB  storage.TrustDB
}

// GetSegments gets the stored in the PathDB.
func (s *Server) GetSegments(w http.ResponseWriter, r *http.Request, params GetSegmentsParams) {
	q := query.Params{}
	var errs serrors.List
	if params.StartIsdAs != nil {
		if ia, err := addr.IAFromString(string(*params.StartIsdAs)); err == nil {
			q.StartsAt = []addr.IA{ia}
		} else {
			errs = append(errs, serrors.WithCtx(err, "parameter", "start_isd_as"))
		}
	}
	if params.EndIsdAs != nil {
		if ia, err := addr.IAFromString(string(*params.EndIsdAs)); err == nil {
			q.EndsAt = []addr.IA{ia}
		} else {
			errs = append(errs, serrors.WithCtx(err, "parameter", "end_isd_as"))
		}
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
	res, err := s.Segments.Get(r.Context(), &q)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting segments",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	sort.Sort(query.Results(res))
	rep := make([]*SegmentBrief, 0, len(res))
	for _, segRes := range res {
		rep = append(rep, &SegmentBrief{
			Id:         SegmentID(segID(segRes.Seg)),
			StartIsdAs: IsdAs(segRes.Seg.FirstIA().String()),
			EndIsdAs:   IsdAs(segRes.Seg.LastIA().String()),
			Length:     len(segRes.Seg.ASEntries),
		})
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

// GetSegment gets a segments details specified by its ID.
func (s *Server) GetSegment(w http.ResponseWriter, r *http.Request, segmentId SegmentIDs) {
	ids, err := decodeSegmentIDs(segmentId)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusBadRequest,
			Title:  "malformed query parameters",
			Type:   api.StringRef(api.BadRequest),
		})
		return
	}
	resp, err := s.getSegmentsByID(r.Context(), ids)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting segments",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	rep := make([]*Segment, 0, len(resp))
	for _, segRes := range resp {
		var hops []Hop
		for i, as := range segRes.Seg.ASEntries {
			if i != 0 {
				hops = append(hops, Hop{
					Interface: int(as.HopEntry.HopField.ConsIngress),
					IsdAs:     IsdAs(as.Local.String())})
			}
			if i != len(segRes.Seg.ASEntries)-1 {
				hops = append(hops, Hop{
					Interface: int(as.HopEntry.HopField.ConsEgress),
					IsdAs:     IsdAs(as.Local.String())})
			}
		}
		rep = append(rep, &Segment{
			Id:          SegmentID(segID(segRes.Seg)),
			Timestamp:   segRes.Seg.Info.Timestamp.UTC(),
			Expiration:  segRes.Seg.MinExpiry().UTC(),
			LastUpdated: segRes.LastUpdate.UTC(),
			Hops:        hops,
		})
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

// GetSegmentBlob gets a segment (specified by its ID) as a pem encoded blob.
func (s *Server) GetSegmentBlob(w http.ResponseWriter, r *http.Request, segmentId SegmentIDs) {
	ids, err := decodeSegmentIDs(segmentId)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusBadRequest,
			Title:  "malformed query parameters",
			Type:   api.StringRef(api.BadRequest),
		})
		return
	}
	resp, err := s.getSegmentsByID(r.Context(), ids)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting segments",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	var buf bytes.Buffer
	for _, segRes := range resp {
		bytes, err := proto.Marshal(seg.PathSegmentToPB(segRes.Seg))
		if err != nil {
			Error(w, Problem{
				Detail: api.StringRef(err.Error()),
				Status: http.StatusInternalServerError,
				Title:  "unable to marshal segment",
				Type:   api.StringRef(api.InternalError),
			})
			return
		}
		b := &pem.Block{
			Type:  "PATH SEGMENT",
			Bytes: bytes,
		}
		if err := pem.Encode(&buf, b); err != nil {
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

// GetCertificates lists the certificate chains
func (s *Server) GetCertificates(w http.ResponseWriter,
	r *http.Request, params GetCertificatesParams) {

	w.Header().Set("Content-Type", "application/json")
	q := trust.ChainQuery{Date: time.Now()}
	var errs serrors.List
	if params.IsdAs != nil {
		if ia, err := addr.IAFromString(string(*params.IsdAs)); err == nil {
			q.IA = ia
		} else {
			errs = append(errs, serrors.WithCtx(err, "parameter", "isd_as"))
		}
	}
	if params.ValidAt != nil {
		q.Date = *params.ValidAt
	}
	if params.All != nil && *params.All {
		q.Date = time.Time{}
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
	chains, err := s.TrustDB.Chains(r.Context(), q)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to fetch certificate chains",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	results := make([]ChainBrief, 0, len(chains))
	for _, chain := range chains {
		subject, err := cppki.ExtractIA(chain[0].Subject)
		if err != nil {
			continue
		}
		issuer, err := cppki.ExtractIA(chain[1].Subject)
		if err != nil {
			continue
		}
		results = append(results, ChainBrief{
			Id:      ChainID(fmt.Sprintf("%x", truststorage.ChainID(chain))),
			Issuer:  IsdAs(issuer.String()),
			Subject: IsdAs(subject.String()),
			Validity: Validity{
				NotAfter:  chain[0].NotAfter,
				NotBefore: chain[0].NotBefore,
			},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(results); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal response",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
}

// GetCertificate lists the certificate chain for a given ChainID
func (s *Server) GetCertificate(w http.ResponseWriter, r *http.Request, chainID ChainID) {
	w.Header().Set("Content-Type", "application/json")

	id, err := hex.DecodeString(string(chainID))
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusBadRequest,
			Title:  "malformed query parameters",
			Type:   api.StringRef(api.BadRequest),
		})
		return
	}
	chain, err := s.TrustDB.Chain(r.Context(), id)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to fetch certificate chain",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}

	// We can safely ignore errors, because only valid chains are stored in the
	// database.
	subject, _ := cppki.ExtractIA(chain[0].Subject)
	issuer, _ := cppki.ExtractIA(chain[1].Subject)
	result := Chain{
		Subject: Certificate{
			DistinguishedName: chain[0].Subject.String(),
			IsdAs:             IsdAs(subject.String()),
			SubjectKeyAlgo:    chain[0].PublicKeyAlgorithm.String(),
			SubjectKeyId:      SubjectKeyID(fmt.Sprintf("% X", chain[0].SubjectKeyId)),
			Validity: Validity{
				NotAfter:  chain[0].NotAfter,
				NotBefore: chain[0].NotBefore,
			},
		},
		Issuer: Certificate{
			DistinguishedName: chain[1].Subject.String(),
			IsdAs:             IsdAs(issuer.String()),
			SubjectKeyAlgo:    chain[1].PublicKeyAlgorithm.String(),
			SubjectKeyId:      SubjectKeyID(fmt.Sprintf("% X", chain[1].SubjectKeyId)),
			Validity: Validity{
				NotAfter:  chain[1].NotAfter,
				NotBefore: chain[1].NotBefore,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(result); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal response",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
}

// GetCertificateBlob gnerates a certificate chain blob response encoded as PEM for a given chainId.
func (s *Server) GetCertificateBlob(w http.ResponseWriter, r *http.Request, chainID ChainID) {
	w.Header().Set("Content-Type", "application/x-pem-file")

	id, err := hex.DecodeString(string(chainID))
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusBadRequest,
			Title:  "malformed query parameters",
			Type:   api.StringRef(api.BadRequest),
		})
		return
	}
	chain, err := s.TrustDB.Chain(r.Context(), id)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to fetch certificate chain",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}

	var buf bytes.Buffer
	for _, cert := range chain {
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
			ChainLifetime: fmt.Sprintf("%s", p.Validity),
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

func (s *Server) GetTrcs(w http.ResponseWriter, r *http.Request, params GetTrcsParams) {
	db := s.TrustDB
	q := truststorage.TRCsQuery{Latest: !(params.All != nil && *params.All)}
	if params.Isd != nil {
		q.ISD = make([]addr.ISD, 0, len(*params.Isd))
		for _, isd := range *params.Isd {
			q.ISD = append(q.ISD, addr.ISD(isd))
		}
	}
	trcs, err := db.SignedTRCs(r.Context(), q)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting trcs",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	if trcs == nil {
		Error(w, Problem{
			Status: http.StatusNotFound,
			Title:  "there are no matching trcs",
			Type:   api.StringRef(api.NotFound),
		})
		return
	}
	sort.Sort(trcs)
	rep := make([]*TRCBrief, 0, len(trcs))
	for _, trc := range trcs {
		rep = append(rep, &TRCBrief{
			Id: TRCID{
				BaseNumber:   int(trc.TRC.ID.Base),
				Isd:          int(trc.TRC.ID.ISD),
				SerialNumber: int(trc.TRC.ID.Serial),
			},
		})
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

// GetTrc gets the trc specified by it's isd bas and serial.
func (s *Server) GetTrc(w http.ResponseWriter, r *http.Request, isd int, base int, serial int) {
	db := s.TrustDB
	trc, err := db.SignedTRC(r.Context(), cppki.TRCID{
		ISD:    addr.ISD(isd),
		Serial: scrypto.Version(serial),
		Base:   scrypto.Version(base),
	})
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting trc",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	if trc.IsZero() {
		Error(w, Problem{
			Status: http.StatusNotFound,
			Title: fmt.Sprintf("trc with isd %d, base %d, serial %d does not exist",
				isd, base, serial),
			Type: api.StringRef(api.NotFound),
		})
		return
	}
	authASes := make([]IsdAs, 0, len(trc.TRC.AuthoritativeASes))
	for _, as := range trc.TRC.AuthoritativeASes {
		authASes = append(authASes, IsdAs(addr.IA{I: trc.TRC.ID.ISD, A: as}.String()))
	}
	coreAses := make([]IsdAs, 0, len(trc.TRC.CoreASes))
	for _, as := range trc.TRC.CoreASes {
		coreAses = append(coreAses, IsdAs(addr.IA{I: trc.TRC.ID.ISD, A: as}.String()))
	}
	rep := TRC{
		AuthoritativeAses: authASes,
		CoreAses:          coreAses,
		Description:       trc.TRC.Description,
		Id: TRCID{
			Isd:          int(trc.TRC.ID.ISD),
			BaseNumber:   int(trc.TRC.ID.Base),
			SerialNumber: int(trc.TRC.ID.Serial),
		},
		Validity: Validity{
			NotAfter:  trc.TRC.Validity.NotAfter,
			NotBefore: trc.TRC.Validity.NotBefore,
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

// GetTrcBlob gets the trc encoded pem blob.
func (s *Server) GetTrcBlob(w http.ResponseWriter, r *http.Request, isd int, base int, serial int) {
	db := s.TrustDB
	trc, err := db.SignedTRC(r.Context(), cppki.TRCID{
		ISD:    addr.ISD(isd),
		Serial: scrypto.Version(serial),
		Base:   scrypto.Version(base),
	})
	if trc.IsZero() {
		Error(w, Problem{
			Status: http.StatusNotFound,
			Title: fmt.Sprintf("trc with isd %d, base %d, serial %d does not exist",
				isd, base, serial),
			Type: api.StringRef(api.NotFound),
		})
		return
	}
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting trc",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	if err := pem.Encode(w, &pem.Block{Type: "TRC", Bytes: trc.TRC.Raw}); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal response",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
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
	w.WriteHeader(int(p.Status))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	// no point in catching error here, there is nothing we can do about it anymore.
	enc.Encode(p)
}

// segID makes a hex encoded string of the segment id.
func segID(s *seg.PathSegment) string { return fmt.Sprintf("%x", s.ID()) }

// getSegmentsByID requests the segments and Sort the result according to the requested order.
func (s *Server) getSegmentsByID(ctx context.Context,
	ids [][]byte) (query.Results, error) {
	q := query.Params{SegIDs: ids}
	r, err := s.Segments.Get(ctx, &q)
	for i, id := range ids {
		for j := i; j < len(r); j++ {
			if segID(r[j].Seg) == string(id) {
				r.Swap(i, j)
				break
			}
		}
	}
	return r, err
}

// decodeSegmentIDs converts segment IDs to RawBytes.
func decodeSegmentIDs(ids SegmentIDs) ([][]byte, error) {
	b := make([][]byte, 0, len(ids))
	var errs serrors.List
	for _, segID := range ids {
		if id, err := hex.DecodeString(string(segID)); err == nil {
			b = append(b, id)
		} else {
			errs = append(errs, serrors.WithCtx(err, "parameter", "id"))
		}
	}
	if err := errs.ToError(); err != nil {
		return nil, err
	}
	return b, nil
}
