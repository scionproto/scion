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
	"bytes"
	"net/netip"
	"os"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/private/storage"
)

func TestInitDefaults(t *testing.T) {
	var cfg DRKeyConfig
	cfg.InitDefaults()
	assert.EqualValues(t, DefaultPrefetchEntries, cfg.PrefetchEntries)
	assert.NotNil(t, cfg.Delegation)
}

func TestSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg DRKeyConfig
	cfg.Sample(&sample, nil, nil)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).DisallowUnknownFields().Decode(&cfg)
	require.NoError(t, err, "config:\n%s", sample.String())
	err = cfg.Validate()
	assert.NoError(t, err)
}

func TestDisable(t *testing.T) {
	cases := []struct {
		name          string
		prepareCfg    func(cfg *DRKeyConfig)
		expectEnabled bool
	}{
		{
			name:          "default",
			expectEnabled: false,
		},
		{
			name: "with CacheEntries",
			prepareCfg: func(cfg *DRKeyConfig) {
				cfg.PrefetchEntries = 100
			},
			expectEnabled: false,
		},
		{
			name: "with Level1DB",
			prepareCfg: func(cfg *DRKeyConfig) {
				cfg.Level1DB.Connection = "test"
			},
			expectEnabled: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &DRKeyConfig{}
			cfg.InitDefaults()
			if c.prepareCfg != nil {
				c.prepareCfg(cfg)
			}
			assert.NoError(t, cfg.Validate())
			assert.Equal(t, c.expectEnabled, cfg.Enabled())
		})
	}
}

func TestSecretValueHostListDefaults(t *testing.T) {
	var cfg SecretValueHostList
	cfg.InitDefaults()
	assert.NotNil(t, cfg)
	assert.Empty(t, cfg)
}

func TestSecretValueHostListSyntax(t *testing.T) {
	var cfg SecretValueHostList
	var err error
	sample1 := `scmp = ["1.1.1.1"]`
	err = toml.NewDecoder(bytes.NewReader([]byte(sample1))).DisallowUnknownFields().Decode(&cfg)
	require.NoError(t, err)
	assert.NoError(t, cfg.Validate())

	var cfg2 SecretValueHostList
	sample2 := `scmp = ["not an address"]`
	err = toml.NewDecoder(bytes.NewReader([]byte(sample2))).DisallowUnknownFields().Decode(&cfg2)
	require.NoError(t, err)
	assert.Error(t, cfg2.Validate())
}

func TestToMapPerHost(t *testing.T) {
	var cfg SecretValueHostList
	sample := `scmp = ["1.1.1.1", "2.2.2.2"]`
	ip1111, err := netip.ParseAddr("1.1.1.1")
	require.NoError(t, err)
	ip2222, err := netip.ParseAddr("2.2.2.2")
	require.NoError(t, err)
	err = toml.NewDecoder(bytes.NewReader([]byte(sample))).DisallowUnknownFields().Decode(&cfg)
	require.NoError(t, err)
	assert.NoError(t, cfg.Validate())
	m := cfg.ToAllowedSet()

	assert.Len(t, m, 2)
	assert.Contains(t, m, HostProto{
		Host:  ip1111,
		Proto: drkey.SCMP,
	})
	assert.Contains(t, m, HostProto{
		Host:  ip2222,
		Proto: drkey.SCMP,
	})
}

func TestNewLevel1DB(t *testing.T) {
	cfg := DRKeyConfig{}
	cfg.InitDefaults()
	cfg.Level1DB.Connection = tempFile(t)
	db, err := storage.NewDRKeyLevel1Storage(cfg.Level1DB)
	defer func() {
		db.Close()
		os.Remove(cfg.Level1DB.Connection)
	}()
	assert.NoError(t, err)
	assert.NotNil(t, db)
}

func TestNewSecretValueDB(t *testing.T) {
	cfg := DRKeyConfig{}
	cfg.InitDefaults()
	cfg.SecretValueDB.Connection = tempFile(t)
	db, err := storage.NewDRKeySecretValueStorage(cfg.SecretValueDB)
	defer func() {
		db.Close()
		os.Remove(cfg.Level1DB.Connection)
	}()
	assert.NoError(t, err)
	assert.NotNil(t, db)
}

func tempFile(t *testing.T) string {
	file, err := os.CreateTemp("", "db-test-")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	return name
}
