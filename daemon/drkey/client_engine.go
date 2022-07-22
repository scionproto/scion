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

// Fetcher obtains a end host keys from the local CS.
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
func (s *ClientEngine) GetASHostKey(ctx context.Context,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {

	// is it in storage?
	k, err := s.DB.GetASHostKey(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.ASHostKey{}, serrors.WrapStr("looking up AS-HOST key in DB", err)
	}

	// if not, ask our CS for it
	remoteKey, err := s.Fetcher.ASHostKey(ctx, meta)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("fetching AS-Host key from local CS", err)
	}
	if err = s.DB.InsertASHostKey(ctx, remoteKey); err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("inserting AS-Host key in DB", err)
	}
	return remoteKey, nil
}

// GetHostASKey returns the HostAS key from the local DB or if not found, by asking our local CS.
func (s *ClientEngine) GetHostASKey(ctx context.Context,
	meta drkey.HostASMeta) (drkey.HostASKey, error) {

	// is it in storage?
	k, err := s.DB.GetHostASKey(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.HostASKey{}, serrors.WrapStr("looking up Host-AS key in DB", err)
	}
	// if not, ask our CS for it

	remoteKey, err := s.Fetcher.HostASKey(ctx, meta)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("fetching Host-AS key from local CS", err)
	}
	if err = s.DB.InsertHostASKey(ctx, remoteKey); err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("inserting Host-AS key in DB", err)
	}
	return remoteKey, nil
}

// GetHostHostKey returns the HostHost key from the local DB or if not found,
// by asking our local CS.
func (s *ClientEngine) GetHostHostKey(ctx context.Context,
	meta drkey.HostHostMeta) (drkey.HostHostKey, error) {

	// is it in storage?
	k, err := s.DB.GetHostHostKey(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.HostHostKey{}, serrors.WrapStr("looking up Host-Host key in DB", err)
	}
	// if not, ask our CS for it

	remoteKey, err := s.Fetcher.HostHostKey(ctx, meta)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("fetching Host-Host key from local CS", err)
	}
	if err = s.DB.InsertHostHostKey(ctx, remoteKey); err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("inserting Host-Host key in DB", err)
	}
	return remoteKey, nil
}

// DeleteExpiredKeys will remove any expired keys.
func (s *ClientEngine) DeleteExpiredASHostKeys(ctx context.Context) (int, error) {
	return s.DB.DeleteExpiredASHostKeys(ctx, time.Now())
}

// DeleteExpiredKeys will remove any expired keys.
func (s *ClientEngine) DeleteExpiredHostASKeys(ctx context.Context) (int, error) {
	return s.DB.DeleteExpiredHostASKeys(ctx, time.Now())
}

// DeleteExpiredKeys will remove any expired keys.
func (s *ClientEngine) DeleteExpiredHostHostKeys(ctx context.Context) (int, error) {
	return s.DB.DeleteExpiredHostHostKeys(ctx, time.Now())

}

// NewClientASHostCleaner creates a Cleaner task that removes expired AS-Host keys.
func NewClientASHostCleaner(c interface {
	DeleteExpiredASHostKeys(ctx context.Context) (int, error)
}) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return c.DeleteExpiredASHostKeys(ctx)
	}, "drkey_client_store")
}

// NewClientEngineCleaner creates a Cleaner task that removes expired Host-AS keys.
func NewClientHostASCleaner(c interface {
	DeleteExpiredHostASKeys(ctx context.Context) (int, error)
}) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return c.DeleteExpiredHostASKeys(ctx)
	}, "drkey_client_store")
}

// NewClientEngineCleaner creates a Cleaner task that removes expired Host-Host keys.
func NewClientHostHostCleaner(c interface {
	DeleteExpiredHostHostKeys(ctx context.Context) (int, error)
}) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return c.DeleteExpiredHostHostKeys(ctx)
	}, "drkey_client_store")
}
