// Copyright 2022 ETH Zurich
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
	"github.com/scionproto/scion/pkg/drkey/generic"
	"github.com/scionproto/scion/pkg/drkey/specific"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/storage/cleaner"
)

// Fetcher obtains a Level1 DRKey from a remote CS.
type Fetcher interface {
	Level1(ctx context.Context, meta drkey.Level1Meta) (drkey.Level1Key, error)
}

// Level1PrefetchListKeeper maintains a list for those level1 keys
// that are recently/frequently used.
type Level1PrefetchListKeeper interface {
	//Update updates the keys in Level1Cache based on the Level1Key metadata.
	Update(key Level1PrefetchInfo)
	// GetLevel1InfoArray retrieves an array whose members contains information regarding
	// level1 keys to prefetch.
	Info() []Level1PrefetchInfo
}

// Level1PrefetchInfo contains the information to prefetch level1 keys from remote CSes.
type Level1PrefetchInfo struct {
	IA    addr.IA
	Proto drkey.Protocol
}

// ServiceEngine maintains and provides secret values, level1 keys and prefetching information.
type ServiceEngine interface {
	// Storing SVs in the server allows for the server to still have access to
	// handed out secrets even after rebooting. It is not critical to the server
	// to derive secret values fast, so the lookup operation is acceptable.
	GetSecretValue(ctx context.Context, meta drkey.SecretValueMeta) (drkey.SecretValue, error)
	GetLevel1Key(ctx context.Context, meta drkey.Level1Meta) (drkey.Level1Key, error)
	GetLevel1PrefetchInfo() []Level1PrefetchInfo

	DeriveLevel1(meta drkey.Level1Meta) (drkey.Level1Key, error)
	DeriveASHost(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error)
	DeriveHostAS(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error)
	DeriveHostHost(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error)

	DeleteExpiredSecrets(ctx context.Context) (int, error)
	DeleteExpiredLevel1Keys(ctx context.Context) (int, error)
}

// NewServiceEngineCleaner creates a Cleaner task that removes expired secrets.
func NewServiceSecretCleaner(s ServiceEngine) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return s.DeleteExpiredSecrets(ctx)
	}, "drkey_serv_store")
}

// NewServiceEngineCleaner creates a Cleaner task that removes expired level1 keys.
func NewServiceLevel1Cleaner(s ServiceEngine) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return s.DeleteExpiredLevel1Keys(ctx)
	}, "drkey_serv_store")
}

type fromPrefetcher struct{}

// serviceEngine keeps track of the level 1 drkey keys. It is backed by a drkey.DB.
type serviceEngine struct {
	secretBackend  *secretValueBackend
	localIA        addr.IA
	db             drkey.Level1DB
	fetcher        Fetcher
	prefetchKeeper Level1PrefetchListKeeper
}

var _ ServiceEngine = (*serviceEngine)(nil)

func NewServiceEngine(
	localIA addr.IA,
	svdb drkey.SecretValueDB,
	masterKey []byte,
	keyDur time.Duration,
	level1db drkey.Level1DB,
	fetcher Fetcher,
	listSize int,
) (*serviceEngine, error) {

	list, err := NewLevel1ARC(listSize)
	if err != nil {
		return nil, err
	}
	return &serviceEngine{
		secretBackend:  newSecretValueBackend(svdb, masterKey, keyDur),
		localIA:        localIA,
		db:             level1db,
		fetcher:        fetcher,
		prefetchKeeper: list,
	}, nil
}

// GetSecretValue returns a valid secret value for the provided metadata.
// It tries to retrieve the secret value from persistence, otherwise
// it creates a new one and stores it away.
func (s *serviceEngine) GetSecretValue(
	ctx context.Context,
	meta drkey.SecretValueMeta,
) (drkey.SecretValue, error) {

	return s.secretBackend.getSecretValue(ctx, meta)
}

// GetLevel1Key returns the level 1 drkey from the local DB or, if not found, by asking any CS in
// the source AS of the key. It also updates the Level1Cache, if needed.
func (s *serviceEngine) GetLevel1Key(
	ctx context.Context,
	meta drkey.Level1Meta,
) (drkey.Level1Key, error) {

	key, err := s.getLevel1Key(ctx, meta)
	if err == nil && ctx.Value(fromPrefetcher{}) == nil && meta.SrcIA != s.localIA {
		keyInfo := Level1PrefetchInfo{
			IA:    key.SrcIA,
			Proto: meta.ProtoId,
		}
		s.prefetchKeeper.Update(keyInfo)
	}
	return key, err
}

// DeleteExpiredKeys will remove any expired Secrets.
func (s *serviceEngine) DeleteExpiredSecrets(ctx context.Context) (int, error) {
	return s.secretBackend.deleteExpiredSV(ctx)
}

// DeleteExpiredKeys will remove any expired keys.
func (s *serviceEngine) DeleteExpiredLevel1Keys(ctx context.Context) (int, error) {
	return s.deleteExpiredLevel1Keys(ctx)
}

// GetLevel1PrefetchInfo returns a list of ASes currently in the cache.
func (s *serviceEngine) GetLevel1PrefetchInfo() []Level1PrefetchInfo {
	return s.prefetchKeeper.Info()
}

// DeriveLevel1 returns a Level1 key based on the presented information.
func (s *serviceEngine) DeriveLevel1(meta drkey.Level1Meta) (drkey.Level1Key, error) {
	sv, err := s.GetSecretValue(context.Background(), drkey.SecretValueMeta{
		ProtoId:  meta.ProtoId,
		Validity: meta.Validity,
	})
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("getting secret value", err)
	}
	key, err := deriveLevel1(meta, sv)
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("deriving level 1 key", err)
	}
	return key, nil
}

// DeriveASHost returns an AS-Host key based on the presented information.
func (s *serviceEngine) DeriveASHost(
	ctx context.Context,
	meta drkey.ASHostMeta,
) (drkey.ASHostKey, error) {

	var key drkey.Key
	var err error

	level1Key, err := s.obtainLevel1Key(ctx, meta.ProtoId, meta.Validity, meta.SrcIA, meta.DstIA)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("getting  level1 key", err)
	}

	var deriver interface {
		DeriveASHost(srcHost string, key drkey.Key) (drkey.Key, error)
	} = generic.Deriver{Proto: meta.ProtoId}

	if meta.ProtoId.IsPredefined() {
		deriver = specific.Deriver{}
	}
	key, err = deriver.DeriveASHost(meta.DstHost, level1Key.Key)
	if err != nil {
		return drkey.ASHostKey{}, err
	}
	return drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   level1Key.Epoch,
		SrcIA:   level1Key.SrcIA,
		DstIA:   level1Key.DstIA,
		DstHost: meta.DstHost,
		Key:     key,
	}, nil
}

// DeriveHostAS returns an Host-AS key based on the presented information.
func (s *serviceEngine) DeriveHostAS(
	ctx context.Context,
	meta drkey.HostASMeta,
) (drkey.HostASKey, error) {

	var key drkey.Key
	var err error

	level1Key, err := s.obtainLevel1Key(ctx, meta.ProtoId, meta.Validity, meta.SrcIA, meta.DstIA)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("getting  level1 key", err)
	}

	var deriver interface {
		DeriveHostAS(srcHost string, key drkey.Key) (drkey.Key, error)
	} = generic.Deriver{Proto: meta.ProtoId}

	if meta.ProtoId.IsPredefined() {
		deriver = specific.Deriver{}
	}
	key, err = deriver.DeriveHostAS(meta.SrcHost, level1Key.Key)
	if err != nil {
		return drkey.HostASKey{}, err
	}

	return drkey.HostASKey{
		ProtoId: meta.ProtoId,
		Epoch:   level1Key.Epoch,
		SrcIA:   level1Key.SrcIA,
		DstIA:   level1Key.DstIA,
		SrcHost: meta.SrcHost,
		Key:     key,
	}, nil
}

// DeriveHostHost returns an Host-Host key based on the presented information.
func (s *serviceEngine) DeriveHostHost(
	ctx context.Context,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {

	hostASMeta := drkey.HostASMeta{
		ProtoId:  meta.ProtoId,
		Validity: meta.Validity,
		SrcIA:    meta.SrcIA,
		DstIA:    meta.DstIA,
		SrcHost:  meta.SrcHost,
	}
	var key drkey.Key
	var err error

	hostASKey, err := s.DeriveHostAS(ctx, hostASMeta)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("computing intermediate Host-AS key", err)
	}

	var deriver interface {
		DeriveHostHost(dstHost string, key drkey.Key) (drkey.Key, error)
	} = generic.Deriver{Proto: meta.ProtoId}

	if meta.ProtoId.IsPredefined() {
		deriver = specific.Deriver{}
	}
	key, err = deriver.DeriveHostHost(meta.DstHost, hostASKey.Key)
	if err != nil {
		return drkey.HostHostKey{}, err
	}

	return drkey.HostHostKey{
		ProtoId: hostASKey.ProtoId,
		Epoch:   hostASKey.Epoch,
		SrcIA:   hostASKey.SrcIA,
		DstIA:   hostASKey.DstIA,
		SrcHost: hostASKey.SrcHost,
		DstHost: meta.DstHost,
		Key:     key,
	}, nil
}

func (s *serviceEngine) getLevel1Key(
	ctx context.Context,
	meta drkey.Level1Meta,
) (drkey.Level1Key, error) {

	if meta.SrcIA == s.localIA {
		return s.DeriveLevel1(meta)
	}

	if meta.DstIA != s.localIA {
		return drkey.Level1Key{},
			serrors.New("neither srcIA nor dstIA matches localIA", "srcIA", meta.SrcIA,
				"dstIA", meta.DstIA, "localIA", s.localIA)
	}

	// look up in the DB.
	k, err := s.db.GetLevel1Key(ctx, meta)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.Level1Key{}, serrors.WrapStr("retrieving key from DB", err)
	}

	// get it from another server.
	remoteKey, err := s.fetcher.Level1(ctx, meta)
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("obtaining level 1 key from CS", err)
	}
	// keep it in our DB.
	err = s.db.InsertLevel1Key(ctx, remoteKey)
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("storing obtained key in DB", err)
	}
	return remoteKey, nil
}

func (s *serviceEngine) obtainLevel1Key(
	ctx context.Context,
	proto drkey.Protocol,
	validity time.Time,
	srcIA addr.IA,
	dstIA addr.IA,
) (drkey.Level1Key, error) {

	level1Meta := drkey.Level1Meta{
		Validity: validity,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		ProtoId:  proto,
	}
	if !proto.IsPredefined() {
		proto = drkey.Generic
	}
	return s.getLevel1Key(ctx, level1Meta)

}

func (s *serviceEngine) deleteExpiredLevel1Keys(ctx context.Context) (int, error) {
	return s.db.DeleteExpiredLevel1Keys(ctx, time.Now())
}

func deriveLevel1(meta drkey.Level1Meta, sv drkey.SecretValue) (drkey.Level1Key, error) {
	key, err := specific.Deriver{}.DeriveLevel1(meta.DstIA, sv.Key)
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("computing level1 raw key", err)
	}
	return drkey.Level1Key{
		Epoch:   sv.Epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		ProtoId: sv.ProtoId,
		Key:     key,
	}, nil
}
