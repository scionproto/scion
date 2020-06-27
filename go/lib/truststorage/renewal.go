// Copyright 2018 Anapaya Systems
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

package truststorage

import (
	"fmt"
	"io"
	"strconv"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
	"github.com/scionproto/scion/go/pkg/trust/renewal/sqlite"
)

var _ (config.Config) = (*RenewalDBConf)(nil)

// RenewalDBConf is the configuration for the connection to the renewal database.
type RenewalDBConf map[string]string

// InitDefaults choses the sqlite backend if no backend is set.
func (cfg *RenewalDBConf) InitDefaults() {
	if *cfg == nil {
		*cfg = make(RenewalDBConf)
	}
	m := *cfg
	util.LowerKeys(m)
	if cfg.Backend() == BackendNone {
		m[BackendKey] = string(BackendSqlite)
	}
}

func (cfg *RenewalDBConf) Backend() Backend {
	return Backend((*cfg)[BackendKey])
}

func (cfg *RenewalDBConf) Connection() string {
	return (*cfg)[ConnectionKey]
}

func (cfg *RenewalDBConf) MaxOpenConns() (int, bool) {
	return db.ConfiguredMaxOpenConns(*cfg)
}

func (cfg *RenewalDBConf) MaxIdleConns() (int, bool) {
	return db.ConfiguredMaxIdleConns(*cfg)
}

func (cfg *RenewalDBConf) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(renewalDbSample, ctx[config.ID]))
}

func (cfg *RenewalDBConf) ConfigName() string {
	return "renewal_db"
}

func (cfg *RenewalDBConf) Validate() error {
	if err := db.ValidateConfigLimits(*cfg); err != nil {
		return err
	}
	// Backend and connection can be empty.
	return nil
}

func (cfg *RenewalDBConf) validateBackend() error {
	switch cfg.Backend() {
	case BackendSqlite:
		return nil
	case BackendNone:
		return serrors.New("No backend set")
	}
	return serrors.New("unsupported backend", "backend", cfg.Backend())
}

func (cfg *RenewalDBConf) validateConnection() error {
	if cfg.Connection() == "" {
		return serrors.New("empty connection not allowed")
	}
	return nil
}

func (cfg *RenewalDBConf) parsedBool(key string) (bool, error) {
	val, ok := (*cfg)[key]
	if !ok || val == "" {
		return true, nil
	}
	return strconv.ParseBool(val)
}

// New creates a renewal database from the config.
func (cfg *RenewalDBConf) New() (renewal.DB, error) {
	if err := cfg.validateBackend(); err != nil {
		return nil, err
	}
	if err := cfg.validateConnection(); err != nil {
		return nil, err
	}

	log.Info("Connecting RenewalDB", "backend", cfg.Backend(), "connection", cfg.Connection())
	tdb, err := sqlite.New(cfg.Connection())
	if err != nil {
		return nil, err
	}
	db.SetConnLimits(cfg, tdb)
	return tdb, nil
}
