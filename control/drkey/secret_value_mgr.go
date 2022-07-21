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

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
)

type secretValueBackend struct {
	db          drkey.SecretValueDB
	masterKey   []byte
	keyDuration time.Duration
}

func NewSecretValueBackend(
	db drkey.SecretValueDB,
	masterKey []byte,
	keyDuration time.Duration,
) *secretValueBackend {

	return &secretValueBackend{
		db:          db,
		masterKey:   masterKey,
		keyDuration: keyDuration,
	}
}

func (s *secretValueBackend) deleteExpiredSV(ctx context.Context) (int, error) {
	return s.db.DeleteExpiredValues(ctx, time.Now())
}

func (s *secretValueBackend) getSecretValue(
	ctx context.Context,
	meta drkey.SecretValueMeta,
) (drkey.SecretValue, error) {

	duration := int64(s.keyDuration / time.Second) // duration in seconds
	k, err := s.db.GetValue(ctx, meta, s.masterKey)
	if err == nil {
		return k, nil
	}
	if err != drkey.ErrKeyNotFound {
		return drkey.SecretValue{}, serrors.WrapStr("retrieving SV from db", err)
	}

	idx := meta.Validity.Unix() / duration
	begin := uint32(idx * duration)
	end := begin + uint32(duration)
	epoch := drkey.NewEpoch(begin, end)
	sv, err := drkey.DeriveSV(meta.ProtoId, epoch, s.masterKey)
	if err != nil {
		return drkey.SecretValue{}, serrors.WrapStr("deriving DRKey secret value", err)
	}
	err = s.db.InsertValue(ctx, sv.ProtoId, sv.Epoch)
	if err != nil {
		return drkey.SecretValue{}, serrors.WrapStr("inserting SV in persistence", err)
	}
	return sv, nil
}
