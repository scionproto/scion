// Copyright 2019 Anapaya Systems
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

	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	// ErrBaseNotSupported indicates base TRC insertion is not supported.
	ErrBaseNotSupported = serrors.New("inserting base TRC not supported")
	// ErrValidation indicates a validation error.
	ErrValidation = serrors.New("validation error")
	// ErrVerification indicates a verification error.
	ErrVerification = serrors.New("verification error")
)

// Inserter inserts and verifies trust material into the database.
type Inserter interface {
	// InsertTRC verifies the signed TRC and inserts it into the database.
	// The previous TRC is queried through the provider function, when necessary.
	InsertTRC(ctx context.Context, decTRC decoded.TRC, trcProvider TRCProviderFunc) error
	// InsertChain verifies the signed certificate chain and inserts it into the
	// database. The issuing TRC is queried through the provider function, when
	// necessary.
	InsertChain(ctx context.Context, decChain decoded.Chain, trcProvider TRCProviderFunc) error
}

// TRCProviderFunc provides TRCs. It is used to configure the TRC retrieval
// method of the inserter.
type TRCProviderFunc func(context.Context, TRCID) (*trc.TRC, error)

// DefaultInserter is used to verify and insert trust material into the database.
type DefaultInserter struct {
	BaseInserter
}

// InsertTRC verifies the signed TRC and inserts it into the database.
// The previous TRC is queried through the provider function, when necessary.
func (ins DefaultInserter) InsertTRC(ctx context.Context, decTRC decoded.TRC,
	trcProvider TRCProviderFunc) error {

	l := metrics.InserterLabels{Type: metrics.TRC}
	insert, err := ins.shouldInsertTRC(ctx, decTRC, trcProvider)
	if err != nil {
		metrics.Inserter.Request(l.WithResult(errToLabel(err))).Inc()
		return err
	}
	if !insert {
		metrics.Inserter.Request(l.WithResult(metrics.OkExists)).Inc()
		return nil
	}
	if _, err := ins.DB.InsertTRC(ctx, decTRC); err != nil {
		metrics.Inserter.Request(l.WithResult(metrics.ErrDB)).Inc()
		return serrors.WrapStr("unable to insert TRC", err)
	}
	metrics.Inserter.Request(l.WithResult(metrics.OkInserted)).Inc()
	return nil
}

// InsertChain verifies the signed certificate chain and inserts it into the
// database. The issuing TRC is queried through the provider function, when
// necessary.
func (ins DefaultInserter) InsertChain(ctx context.Context, chain decoded.Chain,
	trcProvider TRCProviderFunc) error {

	l := metrics.InserterLabels{Type: metrics.Chain}
	insert, err := ins.shouldInsertChain(ctx, chain, trcProvider)
	if err != nil {
		metrics.Inserter.Request(l.WithResult(errToLabel(err))).Inc()
		return err
	}
	if !insert {
		metrics.Inserter.Request(l.WithResult(metrics.OkExists)).Inc()
		return nil
	}
	if _, _, err := ins.DB.InsertChain(ctx, chain); err != nil {
		metrics.Inserter.Request(l.WithResult(metrics.ErrDB)).Inc()
		return serrors.WrapStr("unable to insert chain", err)
	}
	metrics.Inserter.Request(l.WithResult(metrics.OkInserted)).Inc()
	return nil
}

// ForwardingInserter is an inserter that always forwards the trust material to the
// certificate server before inserting it into the database. Forwarding must be
// successful, otherwise the material is not inserted into the database.
type ForwardingInserter struct {
	BaseInserter
	Router LocalRouter
	RPC    RPC
}

// InsertTRC verifies the signed TRC and inserts it into the database. The
// previous TRC is queried through the provider function, when necessary. Before
// insertion, the TRC is forwarded to the certificate server. If the certificate
// server does not successfully handle the TRC, the insertion fails.
func (ins ForwardingInserter) InsertTRC(ctx context.Context, decTRC decoded.TRC,
	trcProvider TRCProviderFunc) error {

	logger := log.FromCtx(ctx)
	l := metrics.InserterLabels{Type: metrics.TRC}
	insert, err := ins.shouldInsertTRC(ctx, decTRC, trcProvider)
	if err != nil {
		metrics.Inserter.Request(l.WithResult(errToLabel(err))).Inc()
		return err
	}
	if !insert {
		metrics.Inserter.Request(l.WithResult(metrics.OkExists)).Inc()
		return nil
	}

	cs := ins.Router.chooseServer()
	logger.Debug("[TrustStore:ForwardingInserter] Forward TRC to certificate server",
		"trc", decTRC, "addr", cs)
	if err := ins.RPC.SendTRC(ctx, decTRC.Raw, cs); err != nil {
		metrics.Inserter.Request(l.WithResult(metrics.ErrTransmit)).Inc()
		return serrors.WrapStr("unable to push TRC to certificate server", err, "addr", cs)
	}
	logger.Debug("[TrustStore:ForwardingInserter] Successfully forwarded TRC",
		"trc", decTRC, "addr", cs)
	if _, err := ins.DB.InsertTRC(ctx, decTRC); err != nil {
		metrics.Inserter.Request(l.WithResult(metrics.ErrDB)).Inc()
		return serrors.WrapStr("unable to insert TRC", err)
	}
	metrics.Inserter.Request(l.WithResult(metrics.OkInserted)).Inc()
	return nil
}

// InsertChain verifies the signed certificate chain and inserts it into the
// database. The issuing TRC is queried through the provider function, when
// necessary. Before insertion, the certificate chain is forwarded to the
// certificate server. If the certificate server does not successfully handle
// the certificate chain, the insertion fails.
func (ins ForwardingInserter) InsertChain(ctx context.Context, chain decoded.Chain,
	trcProvider TRCProviderFunc) error {

	logger := log.FromCtx(ctx)
	l := metrics.InserterLabels{Type: metrics.Chain}
	insert, err := ins.shouldInsertChain(ctx, chain, trcProvider)
	if err != nil {
		metrics.Inserter.Request(l.WithResult(errToLabel(err))).Inc()
		return err
	}
	if !insert {
		metrics.Inserter.Request(l.WithResult(metrics.OkExists)).Inc()
		return nil
	}
	cs := ins.Router.chooseServer()
	logger.Debug("[TrustStore:ForwardingInserter] Forward certificate chain to certificate server",
		"chain", chain, "addr", cs)
	if err := ins.RPC.SendCertChain(ctx, chain.Raw, cs); err != nil {
		metrics.Inserter.Request(l.WithResult(metrics.ErrTransmit)).Inc()
		return serrors.WrapStr("unable to push chain to certificate server", err, "addr", cs)
	}
	logger.Debug("[TrustStore:ForwardingInserter] Successfully forwarded certificate chain",
		"chain", chain)
	if _, _, err := ins.DB.InsertChain(ctx, chain); err != nil {
		metrics.Inserter.Request(l.WithResult(metrics.ErrDB)).Inc()
		return serrors.WrapStr("unable to insert chain", err)
	}
	metrics.Inserter.Request(l.WithResult(metrics.OkInserted)).Inc()
	return nil
}

// BaseInserter implements the common functionality of the inserters.
type BaseInserter struct {
	DB ReadWrite
	// Unsafe allows inserts of base TRCs. This is used as a workaround until
	// TAAC support is implemented.
	Unsafe bool
}

func (ins BaseInserter) shouldInsertTRC(ctx context.Context, decTRC decoded.TRC,
	trcProvider TRCProviderFunc) (bool, error) {

	found, err := ins.DB.TRCExists(ctx, decTRC)
	if err != nil {
		return false, err
	}
	if found {
		return false, nil
	}
	if decTRC.TRC.Base() {
		// XXX(roosd): remove when TAACs are supported.
		if ins.Unsafe {
			if _, err := ins.DB.InsertTRC(ctx, decTRC); err != nil {
				return false, serrors.WrapStr("unable to insert base TRC", err)
			}
			return false, nil
		}
		return false, serrors.WithCtx(ErrBaseNotSupported, "trc", decTRC)
	}
	prev, err := trcProvider(ctx, TRCID{ISD: decTRC.TRC.ISD, Version: decTRC.TRC.Version - 1})
	if err != nil {
		return false, serrors.WrapStr("unable to get previous TRC", err,
			"isd", decTRC.TRC.ISD, "version", decTRC.TRC.Version-1)
	}
	if err := ins.checkUpdate(ctx, prev, decTRC); err != nil {
		return false, serrors.WrapStr("error checking TRC update", err)
	}
	return true, nil
}

func (ins BaseInserter) checkUpdate(ctx context.Context, prev *trc.TRC, next decoded.TRC) error {
	validator := trc.UpdateValidator{
		Next: next.TRC,
		Prev: prev,
	}
	if _, err := validator.Validate(); err != nil {
		return serrors.Wrap(ErrValidation, err)
	}
	verifier := trc.UpdateVerifier{
		Next:        next.TRC,
		NextEncoded: next.Signed.EncodedTRC,
		Prev:        prev,
		Signatures:  next.Signed.Signatures,
	}
	if err := verifier.Verify(); err != nil {
		return serrors.Wrap(ErrVerification, err)
	}
	return nil
}

func (ins BaseInserter) shouldInsertChain(ctx context.Context, chain decoded.Chain,
	trcProvider TRCProviderFunc) (bool, error) {

	found, err := ins.DB.ChainExists(ctx, chain)
	if err != nil {
		return false, err
	}
	if found {
		return false, nil
	}
	if err := ins.validateChain(chain); err != nil {
		return false, serrors.WrapStr("error validating the certificate chain", err)
	}
	t, err := trcProvider(ctx, TRCID{
		ISD:     chain.Issuer.Subject.I,
		Version: chain.Issuer.Issuer.TRCVersion,
	})
	if err != nil {
		return false, serrors.WrapStr("unable to get issuing TRC", err,
			"isd", chain.Issuer.Subject.I, "version", chain.Issuer.Issuer.TRCVersion)
	}
	if err := ins.verifyChain(chain, t); err != nil {
		return false, serrors.WrapStr("error verifying the certificate chain", err)
	}
	return true, nil
}

func (ins BaseInserter) validateChain(chain decoded.Chain) error {
	if err := chain.Issuer.Validate(); err != nil {
		return serrors.Wrap(ErrValidation, err, "part", "issuer")
	}
	if err := chain.AS.Validate(); err != nil {
		return serrors.Wrap(ErrValidation, err, "part", "AS")
	}
	return nil
}

func (ins BaseInserter) verifyChain(chain decoded.Chain, t *trc.TRC) error {
	issVerifier := cert.IssuerVerifier{
		TRC:          t,
		Issuer:       chain.Issuer,
		SignedIssuer: &chain.Chain.Issuer,
	}
	if err := issVerifier.Verify(); err != nil {
		return serrors.Wrap(ErrVerification, err, "part", "issuer")
	}
	asVerifier := cert.ASVerifier{
		Issuer:   chain.Issuer,
		AS:       chain.AS,
		SignedAS: &chain.Chain.AS,
	}
	if err := asVerifier.Verify(); err != nil {
		return serrors.Wrap(ErrVerification, err, "part", "AS")
	}
	return nil
}
