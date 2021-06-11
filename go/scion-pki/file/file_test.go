// Copyright 2021 Anapaya Systems
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

package file_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/scion-pki/file"
)

func TestWriteFile(t *testing.T) {
	dir, cleanup := xtest.MustTempDir("", "file-write-file-test")
	defer cleanup()

	testCases := map[string]struct {
		Prepare      func(t *testing.T)
		Filename     string
		Perm         os.FileMode
		Opts         []file.Option
		ErrAssertion assert.ErrorAssertionFunc
		Validate     func(t *testing.T, expected []byte)
	}{
		"dir does not exist": {
			Filename:     dir + "/inexistent/file",
			Perm:         0666,
			ErrAssertion: assert.Error,
		},
		"file exist": {
			Filename: dir + "/existing",
			Prepare: func(t *testing.T) {
				err := ioutil.WriteFile(dir+"/existing", []byte("data"), 0666)
				require.NoError(t, err)
			},
			Perm:         0666,
			ErrAssertion: assert.Error,
			Validate: func(t *testing.T, expected []byte) {
				raw, err := ioutil.ReadFile(dir + "/existing")
				require.NoError(t, err)
				require.Equal(t, []byte("data"), raw)
			},
		},
		"file is dir": {
			Filename: dir + "/is-dir",
			Prepare: func(t *testing.T) {
				err := os.Mkdir(dir+"/is-dir", 0777)
				require.NoError(t, err)
			},
			Perm:         0666,
			ErrAssertion: assert.Error,
		},
		"file exist force": {
			Filename: dir + "/existing-force",
			Prepare: func(t *testing.T) {
				err := ioutil.WriteFile(dir+"/existing-force", []byte("data"), 0666)
				require.NoError(t, err)
			},
			Perm:         0600,
			ErrAssertion: assert.NoError,
			Opts:         []file.Option{file.WithForce(true)},
			Validate: func(t *testing.T, expected []byte) {
				raw, err := ioutil.ReadFile(dir + "/existing-force")
				require.NoError(t, err)
				require.Equal(t, expected, raw)

				info, err := os.Stat(dir + "/existing-force")
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0600), info.Mode())
			},
		},
		"file exist backup": {
			Filename: dir + "/existing-backup",
			Prepare: func(t *testing.T) {
				err := ioutil.WriteFile(dir+"/existing-backup", []byte("data"), 0666)
				require.NoError(t, err)
			},
			Perm:         0600,
			ErrAssertion: assert.NoError,
			Opts:         []file.Option{file.WithBackup("backup")},
			Validate: func(t *testing.T, expected []byte) {
				raw, err := ioutil.ReadFile(dir + "/existing-backup")
				require.NoError(t, err)
				require.Equal(t, expected, raw)

				info, err := os.Stat(dir + "/existing-backup")
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0600), info.Mode())

				original, err := ioutil.ReadFile(dir + "/existing-backup.backup")
				require.NoError(t, err)
				require.Equal(t, []byte("data"), original)

			},
		},
		"file exist backup extension": {
			Filename: dir + "/existing-backup.ext",
			Prepare: func(t *testing.T) {
				err := ioutil.WriteFile(dir+"/existing-backup.ext", []byte("data"), 0666)
				require.NoError(t, err)
			},
			Perm:         0600,
			ErrAssertion: assert.NoError,
			Opts:         []file.Option{file.WithBackup("backup")},
			Validate: func(t *testing.T, expected []byte) {
				raw, err := ioutil.ReadFile(dir + "/existing-backup.ext")
				require.NoError(t, err)
				require.Equal(t, expected, raw)

				info, err := os.Stat(dir + "/existing-backup.ext")
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0600), info.Mode())

				original, err := ioutil.ReadFile(dir + "/existing-backup.backup.ext")
				require.NoError(t, err)
				require.Equal(t, []byte("data"), original)
			},
		},
		"file exist force and backup": {
			Filename: dir + "/force-backup.ext",
			Prepare: func(t *testing.T) {
				err := ioutil.WriteFile(dir+"/force-backup.ext", []byte("data"), 0666)
				require.NoError(t, err)
			},
			Perm:         0600,
			ErrAssertion: assert.NoError,
			Opts:         []file.Option{file.WithForce(true), file.WithBackup("backup")},
			Validate: func(t *testing.T, expected []byte) {
				raw, err := ioutil.ReadFile(dir + "/force-backup.ext")
				require.NoError(t, err)
				require.Equal(t, expected, raw)

				info, err := os.Stat(dir + "/force-backup.ext")
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0600), info.Mode())

				original, err := ioutil.ReadFile(dir + "/force-backup.backup.ext")
				require.NoError(t, err)
				require.Equal(t, []byte("data"), original)
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if tc.Prepare != nil {
				tc.Prepare(t)
			}
			data := []byte("test")
			err := file.WriteFile(tc.Filename, data, tc.Perm, tc.Opts...)
			tc.ErrAssertion(t, err)
			if tc.Validate != nil {
				tc.Validate(t, data)
			}
		})
	}
}
