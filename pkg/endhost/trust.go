// Copyright 2026 ETH Zurich
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

package endhost

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/patrickmn/go-cache"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/proto/endhost/v1/endhostconnect"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/private/trust"
)

type trustServiceProvider struct {
	ts *TrustService
}

func (p *trustServiceProvider) NotifyTRC(ctx context.Context, id cppki.TRCID,
	opts ...trust.Option) error {
	return nil
}

func chainToCerts(c *Chain) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	asCert, err := x509.ParseCertificate(c.AsCert)
	if err != nil {
		return nil, serrors.Wrap("parsing AS certificate", err)
	}
	caCert, err := x509.ParseCertificate(c.CaCert)
	if err != nil {
		return nil, serrors.Wrap("parsing CA certificate", err)
	}
	chain = append(chain, asCert, caCert)
	return chain, nil
}

func (p *trustServiceProvider) GetChains(ctx context.Context, query trust.ChainQuery,
	opts ...trust.Option) ([][]*x509.Certificate, error) {

	var certs [][]*x509.Certificate
	chains, err := p.ts.GetChains(ctx, []Subject{
		{
			IA:           query.IA,
			SubjectKeyId: query.SubjectKeyID,
		},
	}, query.Validity)
	if err != nil {
		return nil, err
	}
	for _, chain := range chains {
		cert, err := chainToCerts(&Chain{
			AsCert:  chain.AsCert,
			CaCert:  chain.CaCert,
			Subject: chain.Subject,
		})
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func (p *trustServiceProvider) GetSignedTRC(ctx context.Context, id cppki.TRCID,
	opts ...trust.Option) (cppki.SignedTRC, error) {

	trcBytes, err := p.ts.GetTRC(ctx, uint32(id.ISD), uint64(id.Base), uint64(id.Serial))
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	return cppki.DecodeSignedTRC(trcBytes)
}

type TrustService struct {
	verifier trust.Verifier
	provider *trustServiceProvider
	trustDB  trust.DB
	client   endhostconnect.TrustServiceClient
}

func NewTrustService(url string, trustDB trust.DB, httpClient *http.Client) *TrustService {
	provider := &trustServiceProvider{}
	t := &TrustService{
		client:   endhostconnect.NewTrustServiceClient(httpClient, url),
		provider: provider,
		verifier: trust.Verifier{
			Engine: provider,
			Cache:  cache.New(time.Minute, time.Minute),
		},
		trustDB: trustDB,
	}
	provider.ts = t
	return t
}

type Subject struct {
	IA           addr.IA
	SubjectKeyId []byte
}

type Chains struct {
	Chains []Chain
}

type Chain struct {
	AsCert  []byte
	CaCert  []byte
	Subject Subject
}

// GetChains checks for all subjects whether the trustDB already contains a valid chain,
// then it creates a list of subjects for which no valid chain is found and performs a ListChains
// request for these subjects. The returned chains are stored in the trustDB and the function
// returns the chains for all requested subjects.
func (t *TrustService) GetChains(ctx context.Context, subjects []Subject,
	validity cppki.Validity) ([]Chain, error) {

	req := &connect.Request[endhost.ListChainsRequest]{
		Msg: &endhost.ListChainsRequest{
			Subjects:          make([]*endhost.Subject, 0, len(subjects)),
			AtLeastValidUntil: uint32(validity.NotBefore.Unix()),
			AtLeastValidSince: uint32(validity.NotAfter.Unix()),
		},
	}
	chains := []Chain{}
	for _, subject := range subjects {
		query := trust.ChainQuery{
			IA:           subject.IA,
			SubjectKeyID: subject.SubjectKeyId,
			Validity:     validity,
		}
		certs, err := t.trustDB.Chains(ctx, query)
		if err != nil {
			return nil, err
		}
		if len(certs) != 0 {
			for _, chain := range certs {
				chains = append(chains, Chain{
					Subject: Subject{
						IA:           subject.IA,
						SubjectKeyId: subject.SubjectKeyId,
					},
					AsCert: chain[0].Raw,
					CaCert: chain[1].Raw,
				})
			}
		} else {
			req.Msg.Subjects = append(req.Msg.Subjects, &endhost.Subject{
				IsdAs:        uint64(subject.IA),
				SubjectKeyId: subject.SubjectKeyId,
			})
		}
	}
	if len(req.Msg.Subjects) == 0 {
		return chains, nil
	}
	repChains, err := t.client.ListChains(ctx, req)
	metricListChainsTotal.Increment(err)
	if err != nil {
		return nil, serrors.Wrap("on ListChains", err)
	}

	for _, chain := range repChains.Msg.Chains {
		c := Chain{
			Subject: Subject{
				IA:           addr.IA(chain.Subject.IsdAs),
				SubjectKeyId: chain.Subject.SubjectKeyId,
			},
			AsCert: chain.AsCert,
			CaCert: chain.CaCert,
		}
		certs, err := chainToCerts(&c)
		if err != nil {
			return nil, err
		}
		_, err = t.trustDB.InsertChain(ctx, certs)
		if err != nil {
			return nil, err
		}
		chains = append(chains, c)
	}
	return chains, nil
}

// GetTRC checks whether the requested TRC is already stored in the trustDB and returns it if found.
// Otherwise it performs a TRC request, stores the returned TRC in the trustDB and returns it.
func (t *TrustService) GetTRC(ctx context.Context, isd uint32, base uint64, serial uint64) (
	[]byte, error) {

	trcID := cppki.TRCID{
		ISD:    addr.ISD(isd),
		Base:   scrypto.Version(base),
		Serial: scrypto.Version(serial),
	}
	trc, err := t.trustDB.SignedTRC(ctx, trcID)
	if err != nil {
		return nil, err
	}
	if !trc.IsZero() {
		return trc.Raw, nil
	}
	rep, err := t.client.GetTrc(ctx, &connect.Request[endhost.TRCRequest]{
		Msg: &endhost.TRCRequest{
			Isd:    isd,
			Base:   base,
			Serial: serial,
		},
	})
	metricGetTRCTotal.Increment(err)
	if err != nil {
		return nil, serrors.Wrap("on TRC", err)
	}
	trc, err = cppki.DecodeSignedTRC(rep.Msg.Trc)
	if err != nil {
		return nil, serrors.WrapNoStack("parsing TRC", err)
	}
	_, err = t.trustDB.InsertTRC(ctx, trc)
	if err != nil {
		return nil, serrors.WrapNoStack("inserting TRC", err)
	}
	return rep.Msg.Trc, nil
}

// VerifyPathSegments extracts the subjects from all AS entries in all provided path segments,
// performs a ListChains request to obtain the corresponding chains and stores them in the pathdb.
// It then uses the verifer to perform the segment verification.
// An error slice of length equal to the number of segments is returned where each entry is nil
// if the corresponding segment is valid or contains the verification error if it is not valid.
func (t *TrustService) VerifyPathSegments(ctx context.Context, segments []*seg.PathSegment) (
	[]error, error) {

	subjects := []Subject{}
	var globalNotBefore time.Time
	var globalNotAfter time.Time
	first := true
	for _, segment := range segments {
		for _, asEntry := range segment.ASEntries {
			notBefore := segment.Info.Timestamp
			notAfter := segment.Info.Timestamp.Add(
				path.ExpTimeToDuration(asEntry.HopEntry.HopField.ExpTime),
			)
			if first {
				globalNotBefore = notBefore
				globalNotAfter = notAfter
			} else {
				if notBefore.Before(globalNotBefore) {
					globalNotBefore = notBefore
				}
				if notAfter.After(globalNotAfter) {
					globalNotAfter = notAfter
				}
			}
		}
	}
	validity := cppki.Validity{
		NotBefore: globalNotBefore,
		NotAfter:  globalNotAfter,
	}
	for _, segment := range segments {
		for _, asEntry := range segment.ASEntries {
			hdr, err := signed.ExtractUnverifiedHeader(asEntry.Signed)
			if err != nil {
				return nil, serrors.Wrap("extracting unverified header", err)
			}
			var keyID cppb.VerificationKeyID
			if err := proto.Unmarshal(hdr.VerificationKeyID, &keyID); err != nil {
				return nil, serrors.Wrap("parsing verification key ID", err)
			}
			if len(keyID.SubjectKeyId) == 0 {
				return nil, serrors.Wrap("subject key ID must be set", err)
			}
			ia := addr.IA(keyID.IsdAs)
			if ia.IsWildcard() {
				return nil, serrors.New("ISD-AS must not contain wildcard", "isd_as", ia)
			}
			subjects = append(subjects, Subject{
				IA:           ia,
				SubjectKeyId: keyID.SubjectKeyId,
			})
		}
	}
	_, err := t.GetChains(ctx, subjects, validity)
	if err != nil {
		return nil, serrors.Wrap("on list chains", err)
	}
	verificationErrors := make([]error, len(segments))
	for i, segment := range segments {
		if err := segment.Verify(ctx, t.verifier); err != nil {
			verificationErrors[i] = err
		}
	}
	return verificationErrors, nil
}
