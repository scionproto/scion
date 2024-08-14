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

package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	api "github.com/scionproto/scion/private/mgmtapi"
	"github.com/scionproto/scion/private/storage"
	truststorage "github.com/scionproto/scion/private/storage/trust"
	"github.com/scionproto/scion/private/trust"
)

type Server struct {
	TrustDB storage.TrustDB
}

// GetCertificates lists the certificate chains
func (s *Server) GetCertificates(
	w http.ResponseWriter,
	r *http.Request,
	params GetCertificatesParams,
) {

	w.Header().Set("Content-Type", "application/json")
	now := time.Now()
	q := trust.ChainQuery{
		Validity: cppki.Validity{
			NotBefore: now,
			NotAfter:  now,
		},
	}
	var errs serrors.List
	if params.IsdAs != nil {
		if ia, err := addr.ParseIA(*params.IsdAs); err == nil {
			q.IA = ia
		} else {
			errs = append(errs, serrors.Wrap("parsing isd_as", err, "parameter", "isd_as"))
		}
	}
	if params.ValidAt != nil {
		q.Validity = cppki.Validity{
			NotBefore: *params.ValidAt,
			NotAfter:  *params.ValidAt,
		}
	}
	if params.All != nil && *params.All {
		q.Validity = cppki.Validity{}
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
			Id:      fmt.Sprintf("%x", truststorage.ChainID(chain)),
			Issuer:  issuer.String(),
			Subject: subject.String(),
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

	id, err := hex.DecodeString(chainID)
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
			IsdAs:             subject.String(),
			SubjectKeyAlgo:    chain[0].PublicKeyAlgorithm.String(),
			SubjectKeyId:      fmt.Sprintf("% X", chain[0].SubjectKeyId),
			Validity: Validity{
				NotAfter:  chain[0].NotAfter,
				NotBefore: chain[0].NotBefore,
			},
		},
		Issuer: Certificate{
			DistinguishedName: chain[1].Subject.String(),
			IsdAs:             issuer.String(),
			SubjectKeyAlgo:    chain[1].PublicKeyAlgorithm.String(),
			SubjectKeyId:      fmt.Sprintf("% X", chain[1].SubjectKeyId),
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

	id, err := hex.DecodeString(chainID)
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
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) GetTrcs(
	w http.ResponseWriter,
	r *http.Request,
	params GetTrcsParams, // nolint - name from published API
) {

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

// GetTrc gets the trc specified by it's isd base and serial.
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
		authASes = append(authASes, addr.MustIAFrom(trc.TRC.ID.ISD, as).String())
	}
	coreAses := make([]IsdAs, 0, len(trc.TRC.CoreASes))
	for _, as := range trc.TRC.CoreASes {
		coreAses = append(coreAses, addr.MustIAFrom(trc.TRC.ID.ISD, as).String())
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
	w.Header().Set("Content-Type", "application/x-pem-file")

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

// Error creates an detailed error response.
func Error(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	// no point in catching error here, there is nothing we can do about it anymore.
	_ = enc.Encode(p)
}
