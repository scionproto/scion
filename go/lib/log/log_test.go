// Copyright 2018 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

package log_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSetup(t *testing.T) {
	tmpDir, cleanF := xtest.MustTempDir("", "test-folder")
	defer cleanF()

	tests := map[string]struct {
		cfg       log.Config
		assertErr assert.ErrorAssertionFunc
	}{
		"empty, no error": {
			cfg:       log.Config{},
			assertErr: assert.NoError,
		},
		"invalid file level": {
			cfg:       log.Config{File: log.FileConfig{Path: "test/foo", Level: "invalid"}},
			assertErr: assert.Error,
		},
		"invalid console level": {
			cfg:       log.Config{Console: log.ConsoleConfig{Level: "invalid"}},
			assertErr: assert.Error,
		},
		"cannot create, errors": {
			cfg:       log.Config{File: log.FileConfig{Path: "/sys/aka/doesnt/exist"}},
			assertErr: assert.Error,
		},

		"can create, nil": {
			cfg:       log.Config{File: log.FileConfig{Path: filepath.Join(tmpDir, "new")}},
			assertErr: assert.NoError,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := log.Setup(test.cfg)
			test.assertErr(t, err)
		})
	}
}
