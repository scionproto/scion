// Copyright 2019 ETH Zurich
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
	"io"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/storage/db"
)

var ErrKeyNotFound = serrors.New("Key not found")

// SecretValueDB is the database for Secret Values.
type SecretValueDB interface {
	GetSV(ctx context.Context, meta SVMeta) (SV, error)
	InsertSV(ctx context.Context, key SV) error
	DeleteExpiredSV(ctx context.Context, cutoff time.Time) (int64, error)

	io.Closer
	db.LimitSetter
}

// Lvl1DB is the drkey database interface for level 1.
type Lvl1DB interface {
	GetLvl1Key(ctx context.Context, meta Lvl1Meta) (Lvl1Key, error)
	InsertLvl1Key(ctx context.Context, key Lvl1Key) error
	DeleteExpiredLvl1Keys(ctx context.Context, cutoff time.Time) (int64, error)

	io.Closer
	db.LimitSetter
}

// Lvl2DB is the drkey database interface for end-host keys.
type Lvl2DB interface {
	GetASHostKey(ctx context.Context, meta ASHostMeta) (ASHostKey, error)
	GetHostASKey(ctx context.Context, meta HostASMeta) (HostASKey, error)
	GetHostHostKey(ctx context.Context, meta HostHostMeta) (HostHostKey, error)
	InsertASHostKey(ctx context.Context, key ASHostKey) error
	InsertHostASKey(ctx context.Context, key HostASKey) error
	InsertHostHostKey(ctx context.Context, key HostHostKey) error
	DeleteExpiredLvl2Keys(ctx context.Context, cutoff time.Time) (int64, error)

	io.Closer
	db.LimitSetter
}
