// Copyright 2020 ETH Zurich
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

package drkey

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/storage/cleaner"
)

// Fetcher obtains end host keys from the local CS.
type Fetcher interface {
	ASHostKey(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error)
	HostASKey(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error)
	HostHostKey(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error)
}

// ClientEngine is the DRKey store used in the client side.
type ClientEngine struct {
	IA      addr.IA
	DB      drkey.Level2DB
	Fetcher Fetcher
}

// GetASHostKey returns the ASHost key from the local DB or if not found, by asking our local CS.
func (e *ClientEngine) GetASHostKey(
	ctx context.Context,
	meta drkey.ASHostMeta,
) (drkey.ASHostKey, error) {

	// is it in storage?
	k, err := e.DB.GetASHostKey(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.ASHostKey{}, serrors.WrapStr("looking up AS-HOST key in DB", err)
	}

	// if not, ask our CS for it
	remoteKey, err := e.Fetcher.ASHostKey(ctx, meta)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("fetching AS-Host key from local CS", err)
	}
	if err = e.DB.InsertASHostKey(ctx, remoteKey); err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("inserting AS-Host key in DB", err)
	}
	return remoteKey, nil
}

// GetHostASKey returns the HostAS key from the local DB or if not found, by asking our local CS.
func (e *ClientEngine) GetHostASKey(
	ctx context.Context,
	meta drkey.HostASMeta,
) (drkey.HostASKey, error) {

	// is it in storage?
	k, err := e.DB.GetHostASKey(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.HostASKey{}, serrors.WrapStr("looking up Host-AS key in DB", err)
	}

	// if not, ask our CS for it
	remoteKey, err := e.Fetcher.HostASKey(ctx, meta)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("fetching Host-AS key from local CS", err)
	}
	if err = e.DB.InsertHostASKey(ctx, remoteKey); err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("inserting Host-AS key in DB", err)
	}
	return remoteKey, nil
}

// GetHostHostKey returns the HostHost key from the local DB or if not found,
// by asking our local CS.
func (e *ClientEngine) GetHostHostKey(
	ctx context.Context,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {

	// is it in storage?
	k, err := e.DB.GetHostHostKey(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.HostHostKey{}, serrors.WrapStr("looking up Host-Host key in DB", err)
	}

	// if not, ask our CS for it
	remoteKey, err := e.Fetcher.HostHostKey(ctx, meta)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("fetching Host-Host key from local CS", err)
	}
	if err = e.DB.InsertHostHostKey(ctx, remoteKey); err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("inserting Host-Host key in DB", err)
	}
	return remoteKey, nil
}

// CreateStorageCleaners creates three Cleaner tasks that removes
// AS-Host, Host-AS and Host-Host keys respectively.
func (e *ClientEngine) CreateStorageCleaners() []*cleaner.Cleaner {
	cleaners := make([]*cleaner.Cleaner, 3)
	cleaners[0] = cleaner.New(func(ctx context.Context) (int, error) {
		return e.DB.DeleteExpiredASHostKeys(ctx, time.Now())
	}, "drkey_client_as_host_store")
	cleaners[1] = cleaner.New(func(ctx context.Context) (int, error) {
		return e.DB.DeleteExpiredHostASKeys(ctx, time.Now())
	}, "drkey_client_host_as_store")
	cleaners[2] = cleaner.New(func(ctx context.Context) (int, error) {
		return e.DB.DeleteExpiredHostHostKeys(ctx, time.Now())
	}, "drkey_client_host_host_store")
	return cleaners
}
