// Copyright 2025 ETH Zurich
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
	"errors"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/trust"
	trustgrpc "github.com/scionproto/scion/private/trust/grpc"
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

// NewEngine builds the trust engine backed by the trust database.
func NewEngine(
	ctx context.Context,
	certsDir string,
	ia addr.IA,
	db trust.DB,
	dialer grpc.Dialer,
) (trust.Engine, error) {
	loaded, err := trust.LoadTRCs(ctx, certsDir, db)
	if err != nil {
		return trust.Engine{}, serrors.Wrap("loading TRCs", err)
	}
	log.Info("TRCs loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		if errors.Is(r, trust.ErrAlreadyExists) {
			log.Debug("Ignoring existing TRC", "file", f)
			continue
		}
		log.Info("Ignoring non-TRC", "file", f, "reason", r)
	}
	loaded, err = trust.LoadChains(ctx, certsDir, db)
	if err != nil {
		return trust.Engine{}, serrors.Wrap("loading certificate chains",
			err)
	}
	log.Info("Certificate chains loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		if errors.Is(r, trust.ErrAlreadyExists) {
			log.Debug("Ignoring existing certificate chain", "file", f)
			continue
		}
		if errors.Is(r, trust.ErrOutsideValidity) {
			log.Debug("Ignoring certificate chain outside validity", "file", f)
			continue
		}
		log.Info("Ignoring non-certificate chain", "file", f, "reason", r)
	}
	return trust.Engine{
		Inspector: trust.DBInspector{DB: db},
		Provider: trust.FetchingProvider{
			DB: db,
			Fetcher: trustgrpc.Fetcher{
				IA:       ia,
				Dialer:   dialer,
				Requests: metrics.NewPromCounter(trustmetrics.RPC.Fetches),
			},
			Recurser: trust.LocalOnlyRecurser{},
			Router:   trust.LocalRouter{IA: ia},
		},
		DB: db,
	}, nil
}
