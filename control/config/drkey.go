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

package config

import (
	"io"
	"strings"
	"time"

	"inet.af/netaddr"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/storage"
)

const (
	// DefaultEpochDuration is the default duration for the drkey SecretValue and derived keys
	DefaultEpochDuration   = 24 * time.Hour
	DefaultPrefetchEntries = 10000
	EnvVarEpochDuration    = "SCION_TESTING_DRKEY_EPOCH_DURATION"
)

var _ (config.Config) = (*DRKeyConfig)(nil)

// DRKeyConfig is the configuration for the connection to the trust database.
type DRKeyConfig struct {
	Level1DB        storage.DBConfig    `toml:"level1_db,omitempty"`
	SecretValueDB   storage.DBConfig    `toml:"secret_value_db,omitempty"`
	Delegation      SecretValueHostList `toml:"delegation,omitempty"`
	PrefetchEntries int                 `toml:"prefetch_entries,omitempty"`
}

// InitDefaults initializes values of unset keys and determines if the configuration enables DRKey.
func (cfg *DRKeyConfig) InitDefaults() {
	if cfg.PrefetchEntries == 0 {
		cfg.PrefetchEntries = DefaultPrefetchEntries
	}
	config.InitAll(
		cfg.Level1DB.WithDefault(""),
		cfg.SecretValueDB.WithDefault(""),
		&cfg.Delegation,
	)
}

// Enabled returns true if DRKey is configured. False otherwise.
func (cfg *DRKeyConfig) Enabled() bool {
	return cfg.Level1DB.Connection != ""
}

// Validate validates that all values are parsable.
func (cfg *DRKeyConfig) Validate() error {
	return config.ValidateAll(&cfg.Level1DB, &cfg.SecretValueDB, &cfg.Delegation)
}

// Sample writes a config sample to the writer.
func (cfg *DRKeyConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, drkeySample)
	config.WriteSample(dst, path,
		config.CtxMap{config.ID: idSample},
		config.OverrideName(
			config.FormatData(
				&cfg.Level1DB,
				storage.SetID(storage.SampleDRKeyLevel1DB, idSample).Connection,
			),
			"level1_db",
		),
		config.OverrideName(
			config.FormatData(
				&cfg.SecretValueDB,
				storage.SetID(storage.SampleDRKeySecretValueDB, idSample).Connection,
			),
			"secret_value_db",
		),
		&cfg.Delegation,
	)
}

// ConfigName is the key in the toml file.
func (cfg *DRKeyConfig) ConfigName() string {
	return "drkey"
}

// SecretValueHostList configures which endhosts can get delegation secrets, per protocol.
type SecretValueHostList map[string][]string

var _ (config.Config) = (*SecretValueHostList)(nil)

// InitDefaults will not add or modify any entry in the config.
func (cfg *SecretValueHostList) InitDefaults() {
	if *cfg == nil {
		*cfg = make(SecretValueHostList)
	}
}

// Validate validates that the protocols exist, and their addresses are parsable.
func (cfg *SecretValueHostList) Validate() error {
	for proto, list := range *cfg {
		protoString := "PROTOCOL_" + strings.ToUpper(proto)
		protoID, ok := drkey.ProtocolStringToId(protoString)
		if !ok {
			return serrors.New("Configured protocol not found", "protocol", proto)
		}
		if protoID == drkey.Generic {
			return serrors.New("GENERIC protocol is not allowed")
		}
		for _, ip := range list {
			if h := addr.HostFromIPStr(ip); h == nil {
				return serrors.New("Syntax error: not a valid address", "ip", ip)
			}
		}
	}
	return nil
}

// Sample writes a config sample to the writer.
func (cfg *SecretValueHostList) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, drkeySecretValueHostListSample)
}

// ConfigName is the key in the toml file.
func (cfg *SecretValueHostList) ConfigName() string {
	return "delegation"
}

type HostProto struct {
	Host  netaddr.IP
	Proto drkey.Protocol
}

// ToAllowedSet will return map where there is a set of supported (Host,Protocol).
func (cfg *SecretValueHostList) ToAllowedSet() map[HostProto]struct{} {
	m := make(map[HostProto]struct{})
	for proto, ipList := range *cfg {
		for _, ip := range ipList {
			host, err := netaddr.ParseIP(ip)
			if err != nil {
				continue
			}
			protoString := "PROTOCOL_" + strings.ToUpper(proto)
			protoID, ok := drkey.ProtocolStringToId(protoString)
			if !ok {
				continue
			}
			hostProto := HostProto{
				Host:  host,
				Proto: protoID,
			}
			m[hostProto] = struct{}{}
		}
	}
	return m
}
