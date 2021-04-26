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
	"net"
	"time"

	"github.com/opentracing/opentracing-go"
	opentracingext "github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
)

var (
	errNotFound = serrors.New("not found")
	errInactive = serrors.New("inactive")
)

// Fetcher fetches trust material from a remote.
type Fetcher interface {
	// Chains fetches certificate chains that match the query from the remote.
	Chains(ctx context.Context, req ChainQuery, server net.Addr) ([][]*x509.Certificate, error)
	// TRC fetches a specific TRC from the remote.
	TRC(ctx context.Context, id cppki.TRCID, server net.Addr) (cppki.SignedTRC, error)
}

// FetchingProvider provides crypto material. The fetching provider is capable
// of fetching missing crypto material over the network.
type FetchingProvider struct {
	DB       DB
	Recurser Recurser
	Fetcher  Fetcher
	Router   Router
}

// GetChains returns certificate chains that match the chain query. If no chain
// is locally available, they are resolved over the network.
//
// By default, this only returns chains that are verifiable against the
// currently active TRCs, even if the the query date is set to a value in the
// past. To allow chains that are no longer verifiable using the active TRC, but
// that were verifiable in the past, set the AllowInactive option.
//
// Currently, there is no use case for fetching inactive certificate chains from
// a remote and verifying them against a no-longer active TRC. For simplicity,
// this feature is not implemented. Thus, certificate chains that are fetched
// over the network that are not verifiable against the active TRCs are ignored,
// even if the AllowInactive option is set.
func (p FetchingProvider) GetChains(ctx context.Context, query ChainQuery,
	opts ...Option) ([][]*x509.Certificate, error) {

	l := metrics.ProviderLabels{Type: metrics.Chain, Trigger: metrics.FromCtx(ctx)}
	o := applyOptions(opts)

	span, ctx := opentracing.StartSpanFromContext(ctx, "trustengine.get_chains")
	defer span.Finish()
	opentracingext.Component.Set(span, "trust")
	span.SetTag("query.isd_as", query.IA)
	span.SetTag("query.subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID))
	span.SetTag("query.date", util.TimeToCompact(query.Date))

	logger := log.FromCtx(ctx)
	logger.Debug("Getting chains",
		"isd_as", query.IA,
		"date", util.TimeToCompact(query.Date),
		"subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID))

	if query.IA.IsWildcard() {
		return nil, serrors.New("ISD-AS must not contain a wildcard", "isd_as", query.IA)
	}
	if query.Date.IsZero() {
		query.Date = time.Now()
		logger.Debug("Set date for chain request with zero time")
	}

	chains, err := p.DB.Chains(ctx, query)
	if err != nil {
		logger.Info("Failed to get chain from database",
			"query", query, "err", err)
		setProviderMetric(span, l.WithResult(metrics.ErrDB), err)
		return nil, serrors.WrapStr("fetching chains from database", err)
	}

	if o.allowInactive && len(chains) > 0 {
		setProviderMetric(span, l.WithResult(metrics.Success), nil)
		return chains, nil
	}

	trcs, result, err := activeTRCs(ctx, p.DB, query.IA.I)
	if err != nil {
		logger.Info("Failed to get TRC for chain verification",
			"isd", query.IA.I, "err", err)
		setProviderMetric(span, l.WithResult(result), err)
		return nil, serrors.WrapStr("fetching active TRCs from database", err)
	}

	chains = filterVerifiableChains(chains, trcs)
	if len(chains) > 0 {
		setProviderMetric(span, l.WithResult(metrics.Success), nil)
		return chains, nil
	}

	// No chain is available locally. Start fetching chains over the nework, if
	// recursion is allowed.
	if err := p.Recurser.AllowRecursion(o.client); err != nil {
		setProviderMetric(span, l.WithResult(metrics.ErrNotAllowed), err)
		return nil, serrors.WrapStr("recursion not allowed", err)
	}
	if o.server == nil {
		if o.server, err = p.Router.ChooseServer(ctx, query.IA.I); err != nil {
			setProviderMetric(span, l.WithResult(metrics.ErrInternal), err)
			return nil, serrors.WrapStr("choosing server", err)
		}
	}
	if chains, err = p.Fetcher.Chains(ctx, query, o.server); err != nil {
		setProviderMetric(span, l.WithResult(metrics.ErrInternal), err)
		return nil, serrors.WrapStr("fetching chains from remote", err, "server", o.server)
	}

	// For simplicity, we ignore non-verifiable chains.
	chains = filterVerifiableChains(chains, trcs)
	if len(chains) > 0 {
		// FIXME(roosd): Should probably be a transaction.
		for _, chain := range chains {
			if _, err := p.DB.InsertChain(ctx, chain); err != nil {
				setProviderMetric(span, l.WithResult(metrics.ErrInternal), err)
				return nil, serrors.WrapStr("inserting chain into database", err)
			}
		}
	}
	if len(chains) == 0 {
		setProviderMetric(span, l.WithResult(metrics.ErrNotFound), nil)
		return nil, nil
	}
	setProviderMetric(span, l.WithResult(metrics.Success), nil)
	return chains, nil
}

// GetSignedTRC returns the signed TRC. Currently, this method only uses the DB
// and doesn't recurse over the network.
// TODO(lukedirtwalker): add recursing functionality.
func (p FetchingProvider) GetSignedTRC(ctx context.Context, id cppki.TRCID,
	opts ...Option) (cppki.SignedTRC, error) {

	return p.DB.SignedTRC(ctx, id)
}

// NotifyTRC notifies the provider of the existence of a TRC. This method only
// fails in case of a DB, network or verification error.
func (p FetchingProvider) NotifyTRC(ctx context.Context, id cppki.TRCID, opts ...Option) error {
	l := metrics.ProviderLabels{Type: metrics.NotifyTRC, Trigger: metrics.FromCtx(ctx)}
	o := applyOptions(opts)

	span, ctx := opentracing.StartSpanFromContext(ctx, "trustengine.notify_trc")
	defer span.Finish()
	opentracingext.Component.Set(span, "trust")
	span.SetTag("trc_id.isd", id.ISD)
	span.SetTag("trc_id.base", id.Base)
	span.SetTag("trc_id.serial", id.Serial)

	logger := log.FromCtx(ctx)
	logger.Debug("TRC notify", "id", id)

	trc, err := p.DB.SignedTRC(ctx, cppki.TRCID{
		ISD:    id.ISD,
		Base:   scrypto.LatestVer,
		Serial: scrypto.LatestVer,
	})
	if err != nil {
		setProviderMetric(span, l.WithResult(metrics.ErrDB), err)
		return err
	}
	if trc.IsZero() {
		err := serrors.New("no TRC for ISD present", "isd", id.ISD)
		setProviderMetric(span, l.WithResult(metrics.ErrNotFound), err)
		return err
	}
	if trc.TRC.ID.Base != id.Base {
		setProviderMetric(span, l.WithResult(metrics.ErrValidate), nil)
		return serrors.New("base number mismatch", "expected", trc.TRC.ID.Base, "actual", id.Base)
	}
	if id.Serial <= trc.TRC.ID.Serial {
		setProviderMetric(span, l.WithResult(metrics.Success), nil)
		return nil
	}
	if err := p.Recurser.AllowRecursion(o.client); err != nil {
		setProviderMetric(span, l.WithResult(metrics.ErrNotAllowed), err)
		return serrors.WrapStr("recursion not allowed", err)
	}
	if o.server == nil {
		if o.server, err = p.Router.ChooseServer(ctx, id.ISD); err != nil {
			setProviderMetric(span, l.WithResult(metrics.ErrInternal), err)
			return serrors.WrapStr("choosing server", err)
		}
	}
	// In general, we expect only one TRC update missing, thus sequential
	// fetching should be fine here.
	for serial := trc.TRC.ID.Serial + 1; serial <= id.Serial; serial++ {
		toFetch := cppki.TRCID{ISD: id.ISD, Base: id.Base, Serial: serial}
		fetched, err := p.Fetcher.TRC(ctx, toFetch, o.server)
		if err != nil {
			setProviderMetric(span, l.WithResult(metrics.ErrInternal), err)
			return serrors.WrapStr("resolving TRC update", err, "id", toFetch)
		}
		if err := fetched.Verify(&trc.TRC); err != nil {
			setProviderMetric(span, l.WithResult(metrics.ErrVerify), err)
			return serrors.WrapStr("verifying TRC update", err, "id", toFetch)
		}
		if _, err := p.DB.InsertTRC(ctx, fetched); err != nil {
			setProviderMetric(span, l.WithResult(metrics.ErrInternal), err)
			return serrors.WrapStr("inserting TRC update", err, "id", toFetch)
		}
		trc = fetched
	}
	return nil
}

func activeTRCs(ctx context.Context, db DB, isd addr.ISD) ([]cppki.SignedTRC, string, error) {
	trc, err := db.SignedTRC(ctx, cppki.TRCID{
		ISD:    isd,
		Base:   scrypto.LatestVer,
		Serial: scrypto.LatestVer,
	})
	if err != nil {
		return nil, metrics.ErrDB, err
	}
	if trc.IsZero() {
		return nil, metrics.ErrNotFound, errNotFound
	}
	// XXX(roosd): This could resolve newer TRCs over the network. However,
	// for every GetChains by the verifier, there should be a NotifyTRC, such
	// that should never run into this condition in the first place.
	if !trc.TRC.Validity.Contains(time.Now()) {
		return nil, metrics.ErrInactive, errInactive
	}
	if !trc.TRC.InGracePeriod(time.Now()) {
		return []cppki.SignedTRC{trc}, metrics.Success, nil
	}
	grace, err := db.SignedTRC(ctx, cppki.TRCID{
		ISD:    isd,
		Base:   trc.TRC.ID.Base,
		Serial: trc.TRC.ID.Serial - 1,
	})
	if err != nil {
		return nil, metrics.ErrDB, err
	}
	if grace.IsZero() {
		return nil, metrics.ErrNotFound, errNotFound
	}
	return []cppki.SignedTRC{trc, grace}, metrics.Success, nil
}

func filterVerifiableChains(chains [][]*x509.Certificate,
	trcs []cppki.SignedTRC) [][]*x509.Certificate {

	verified := make([][]*x509.Certificate, 0, len(chains))
	for _, chain := range chains {
		for _, trc := range trcs {
			verifyOptions := cppki.VerifyOptions{TRC: []*cppki.TRC{&trc.TRC}}
			if err := cppki.VerifyChain(chain, verifyOptions); err == nil {
				verified = append(verified, chain)
				break
			}
		}
	}
	return verified
}

func setProviderMetric(span opentracing.Span, l metrics.ProviderLabels, err error) {
	metrics.Provider.Request(l).Inc()
	tracing.ResultLabel(span, l.Result)
	tracing.Error(span, err)
}
