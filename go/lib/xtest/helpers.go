// Copyright 2018 ETH Zurich
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

package xtest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// TempFileName creates a temporary file in dir with the specified prefix, and
// then closes and deletes the file and returns its name. It is useful for
// testing packages that care about a unique path without being able to
// overwrite it (e.g., UNIX domain socket addresses or databases).
func TempFileName(dir, prefix string) (string, error) {
	file, err := ioutil.TempFile(dir, prefix)
	if err != nil {
		return "", err
	}

	name := file.Name()
	if err := file.Close(); err != nil {
		return "", err
	}

	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

// MustTempFileName is a wrapper around TempFileName. The function panics if an
// error occurs. It is intended for tests where error handling is not
// necessary, and for chaining functions.
func MustTempFileName(dir, prefix string) string {
	name, err := TempFileName(dir, prefix)
	if err != nil {
		panic(err)
	}
	return name
}

// MustTempDir creates a new temporary directory under dir with the specified
// prefix. If the function encounters an error it panics. The second return
// value is a clean-up function that can be called to recursively delete the
// entire directory.
func MustTempDir(dir, prefix string) (string, func()) {
	name, err := ioutil.TempDir(dir, prefix)
	if err != nil {
		panic(err)
	}
	return name, func() {
		os.RemoveAll(name)
	}
}

// FailOnErr causes t to exit with a fatal error if err is non-nil.
func FailOnErr(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

// MustMarshalJSONToFile marshals v and writes the result to file
// testdata/baseName. If the file exists, it is truncated; if it doesn't exist,
// it is created. On errors, t.Fatal() is called.
func MustMarshalJSONToFile(t *testing.T, v interface{}, baseName string) {
	t.Helper()

	enc, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		t.Fatal(err)
	}

	buffer := bytes.NewBuffer(enc)
	if err := buffer.WriteByte('\n'); err != nil {
		t.Fatal(err)
	}

	MustWriteToFile(t, buffer.Bytes(), baseName)
}

// MustWriteToFile writes b to file testdata/baseName. If the file exists, it
// is truncated; if it doesn't exist, it is created. On errors, t.Fatal() is
// called.
func MustWriteToFile(t *testing.T, b []byte, baseName string) {
	t.Helper()

	if err := ioutil.WriteFile(ExpandPath(baseName), b, 0644); err != nil {
		t.Fatal(err)
	}
}

// MustReadFromFile reads testdata/baseName and returns the raw content. On
// errors, t.Fatal() is called.
func MustReadFromFile(t *testing.T, baseName string) []byte {
	t.Helper()

	name := filepath.Join("testdata", baseName)
	b, err := ioutil.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ExpandPath returns testdata/file.
func ExpandPath(file string) string {
	return filepath.Join("testdata", fmt.Sprintf("%s.ref", file))
}
