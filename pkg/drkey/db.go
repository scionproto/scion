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
	"io"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/storage/db"
)

var ErrKeyNotFound = serrors.New("key not found")

// SecretValueDB is the database for Secret Values.
type SecretValueDB interface {
	GetValue(ctx context.Context, meta SecretValueMeta, asSecret []byte) (SecretValue, error)
	InsertValue(ctx context.Context, proto Protocol, epoch Epoch) error
	DeleteExpiredValues(ctx context.Context, cutoff time.Time) (int, error)

	io.Closer
	db.LimitSetter
}

// Level1DB is the drkey database interface for level 1.
type Level1DB interface {
	GetLevel1Key(ctx context.Context, meta Level1Meta) (Level1Key, error)
	InsertLevel1Key(ctx context.Context, key Level1Key) error
	DeleteExpiredLevel1Keys(ctx context.Context, cutoff time.Time) (int, error)

	io.Closer
	db.LimitSetter
}

// Level2DB is the drkey database interface for end-host keys.
type Level2DB interface {
	GetASHostKey(ctx context.Context, meta ASHostMeta) (ASHostKey, error)
	GetHostASKey(ctx context.Context, meta HostASMeta) (HostASKey, error)
	GetHostHostKey(ctx context.Context, meta HostHostMeta) (HostHostKey, error)
	InsertASHostKey(ctx context.Context, key ASHostKey) error
	InsertHostASKey(ctx context.Context, key HostASKey) error
	InsertHostHostKey(ctx context.Context, key HostHostKey) error
	DeleteExpiredASHostKeys(ctx context.Context, cutoff time.Time) (int, error)
	DeleteExpiredHostASKeys(ctx context.Context, cutoff time.Time) (int, error)
	DeleteExpiredHostHostKeys(ctx context.Context, cutoff time.Time) (int, error)

	io.Closer
	db.LimitSetter
}
