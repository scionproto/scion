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

package trust

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/patrickmn/go-cache"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	libmetrics "github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
)

const defaultCacheExpiration = time.Minute

// Verifier is used to verify control plane messages using the AS cert
// stored in the database.
type Verifier struct {
	// BoundIA when non-zero makes sure that only a signature originated from that IA
	// can be valid.
	BoundIA addr.IA
	// BoundServer binds a remote server to ask for missing crypto material.
	BoundServer net.Addr
	// Engine provides verified certificate chains.
	Engine Provider

	// Cache keeps track of recently used certificates. If nil no cache is used.
	// This API is experimental.
	Cache              *cache.Cache
	CacheHits          libmetrics.Counter
	MaxCacheExpiration time.Duration
}

// Verify verifies the signature of the msg.
func (v Verifier) Verify(ctx context.Context, signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte) (*signed.Message, error) {

	l := metrics.VerifierLabels{}
	hdr, err := signed.ExtractUnverifiedHeader(signedMsg)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return nil, err
	}

	var keyID cppb.VerificationKeyID
	if err := proto.Unmarshal(hdr.VerificationKeyID, &keyID); err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return nil, serrors.WrapStr("parsing verification key ID", err)
	}
	if len(keyID.SubjectKeyId) == 0 {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return nil, serrors.WrapStr("subject key ID must be set", err)
	}
	ia := addr.IAInt(keyID.IsdAs).IA()
	if !v.BoundIA.IsZero() && !v.BoundIA.Equal(ia) {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return nil, serrors.New("does not match bound ISD-AS", "expected", v.BoundIA, "actual", ia)
	}
	if ia.IsWildcard() {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return nil, serrors.New("ISD-AS must not contain wildcard", "isd_as", ia)
	}
	if v.Engine == nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, serrors.New("nil engine that provides cert chains")
	}
	id := cppki.TRCID{ISD: ia.I,
		Base:   scrypto.Version(keyID.TrcBase),
		Serial: scrypto.Version(keyID.TrcSerial),
	}
	if err := v.notifyTRC(ctx, id); err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, serrors.WrapStr("reporting TRC", err, "id", id)
	}
	query := ChainQuery{
		IA:           ia,
		SubjectKeyID: keyID.SubjectKeyId,
		Date:         time.Now(),
	}
	chains, err := v.getChains(ctx, query)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, serrors.WrapStr("getting chains", err,
			"query.isd_as", query.IA,
			"query.subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID),
			"query.date", util.TimeToCompact(query.Date),
		)
	}
	for _, c := range chains {
		signedMsg, err := signed.Verify(signedMsg, c[0].PublicKey, associatedData...)
		if err == nil {
			metrics.Verifier.Verify(l.WithResult(metrics.Success)).Inc()
			return signedMsg, nil
		}
	}
	metrics.Verifier.Verify(l.WithResult(metrics.ErrNotFound)).Inc()
	return nil, serrors.New("no chain in database can verify signature",
		"query.isd_as", query.IA,
		"query.subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID),
		"query.date", util.TimeToCompact(query.Date),
	)
}

func (v *Verifier) notifyTRC(ctx context.Context, id cppki.TRCID) error {
	key := fmt.Sprintf("notify-%s", id)
	_, ok := v.cacheGet(key, "notify_trc")
	if ok {
		return nil
	}
	if err := v.Engine.NotifyTRC(ctx, id, Server(v.BoundServer)); err != nil {
		return err
	}
	v.cacheAdd(key, struct{}{}, time.Minute)
	return nil
}

func (v *Verifier) getChains(ctx context.Context, q ChainQuery) ([][]*x509.Certificate, error) {
	key := fmt.Sprintf("chain-%s-%x", q.IA, q.SubjectKeyID)

	cachedChains, ok := v.cacheGet(key, "chains")
	if ok {
		return cachedChains.([][]*x509.Certificate), nil
	}

	chains, err := v.Engine.GetChains(ctx, q, Server(v.BoundServer))
	if err != nil {
		return nil, err
	}
	if chains != nil {
		v.cacheAdd(key, chains, v.cacheExpiration(chains))
	}
	return chains, nil
}

func (v *Verifier) cacheGet(key string, reqType string) (interface{}, bool) {
	if v.Cache == nil {
		return nil, false
	}
	result, ok := v.Cache.Get(key)

	resultValue := "hit"
	if !ok {
		resultValue = "miss"
	}
	libmetrics.CounterInc(libmetrics.CounterWith(v.CacheHits,
		"type", reqType,
		prom.LabelResult, resultValue,
	))

	return result, ok
}

func (v *Verifier) cacheAdd(key string, value interface{}, d time.Duration) {
	if v.Cache == nil {
		return
	}
	v.Cache.Add(key, value, d)
}

func (v *Verifier) cacheExpiration(chains [][]*x509.Certificate) time.Duration {
	dur := v.MaxCacheExpiration
	if dur == 0 {
		dur = defaultCacheExpiration
	}
	validity := time.Duration(rand.Int63n(int64(dur-(dur/2))) + int64(dur/2))
	expiration := time.Now().Add(validity)
	for _, chain := range chains {
		if notAfter := chain[0].NotAfter; notAfter.Before(expiration) {
			expiration = notAfter
		}
	}
	return time.Until(expiration)
}
