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

package db

import (
	"database/sql"
	"strconv"

	"github.com/scionproto/scion/go/lib/serrors"
)

var _ LimitSetter = (*sql.DB)(nil)

const (
	// MaxOpenConnsKey is the configuration key for max open connections.
	MaxOpenConnsKey = "max_open_conns"
	// MaxIdleConnsKey is the configuration key for max idle connections.
	MaxIdleConnsKey = "max_idle_conns"
)

// LimitSetter allows setting the database connection limits.
type LimitSetter interface {
	SetMaxOpenConns(maxOpenConns int)
	SetMaxIdleConns(maxIdleConns int)
}

// LimitConfig is a configuration of database limits.
type LimitConfig interface {
	// MaxOpenConns returns the max open connection count and true if the limit
	// was configured.
	MaxOpenConns() (int, bool)
	// MaxIdleConns returns the max idle connection count and true if the limit
	// was configured.
	MaxIdleConns() (int, bool)
}

// SetConnLimits sets the configured limits on the database.
func SetConnLimits(cfg LimitConfig, db LimitSetter) {
	if m, ok := cfg.MaxOpenConns(); ok {
		db.SetMaxOpenConns(m)
	}
	if m, ok := cfg.MaxIdleConns(); ok {
		db.SetMaxIdleConns(m)
	}
}

// ValidateConfigLimits validates connection limits on the given config map.
func ValidateConfigLimits(cfg map[string]string) error {
	if _, _, err := parsedInt(cfg, MaxOpenConnsKey); err != nil {
		return serrors.New("Invalid MaxOpenConns", "value", cfg[MaxOpenConnsKey])
	}
	if _, _, err := parsedInt(cfg, MaxIdleConnsKey); err != nil {
		return serrors.New("Invalid MaxIdleConns", "value", cfg[MaxIdleConnsKey])
	}
	return nil
}

// ConfiguredMaxOpenConns returns the configured max open connections in the
// config map and returns true if the limit was set.
func ConfiguredMaxOpenConns(cfg map[string]string) (int, bool) {
	val, ok, _ := parsedInt(cfg, MaxOpenConnsKey)
	return val, ok
}

// ConfiguredMaxIdleConns returns the configured max idle connections in the
// config map and returns true if the limit was set.
func ConfiguredMaxIdleConns(cfg map[string]string) (int, bool) {
	val, ok, _ := parsedInt(cfg, MaxIdleConnsKey)
	return val, ok
}

func parsedInt(cfg map[string]string, key string) (int, bool, error) {
	val, ok := cfg[key]
	if !ok || val == "" {
		return 0, false, nil
	}
	i, err := strconv.Atoi(val)
	return i, true, err
}
