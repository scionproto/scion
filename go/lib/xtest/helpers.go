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

package xtest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
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

// CopyDir copies "from" to "to", using the unix cp command.
func CopyDir(t testing.TB, from, to string) {
	t.Helper()
	cmd := exec.Command("cp", "-rL", from, to)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

// FailOnErr causes t to exit with a fatal error if err is non-nil.
func FailOnErr(t testing.TB, err error, desc ...string) {
	t.Helper()

	if err != nil {
		t.Fatal(strings.Join(desc, " "), err)
	}
}

// MustMarshalJSONToFile marshals v and writes the result to file
// testdata/baseName. If the file exists, it is truncated; if it doesn't exist,
// it is created. On errors, t.Fatal() is called.
func MustMarshalJSONToFile(t testing.TB, v interface{}, baseName string) {
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
func MustWriteToFile(t testing.TB, b []byte, baseName string) {
	t.Helper()

	if err := ioutil.WriteFile(ExpandPath(baseName), b, 0644); err != nil {
		t.Fatal(err)
	}
}

// MustReadFromFile reads testdata/baseName and returns the raw content. On
// errors, t.Fatal() is called.
func MustReadFromFile(t testing.TB, baseName string) []byte {
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
	return filepath.Join("testdata", fmt.Sprintf("%s", file))
}

// MustParseIA parses s and returns the corresponding addr.IA object. It
// panics if s is not a valid ISD-AS representation.
func MustParseIA(s string) addr.IA {
	ia, err := addr.IAFromString(s)
	if err != nil {
		panic(err)
	}
	return ia
}

// MustParseAS parses s and returns the corresponding addr.AS object. It panics
// if s is not valid AS representation.
func MustParseAS(s string) addr.AS {
	ia, err := addr.ASFromString(s)
	if err != nil {
		panic(err)
	}
	return ia
}

// MustParseASes parses a list of comma separated AS strings. It panics in case
// parsing fails.
func MustParseASes(list string) []addr.AS {
	l := strings.Split(list, ",")
	var ases []addr.AS
	for _, raw := range l {
		ases = append(ases, MustParseAS(raw))
	}
	return ases
}

// MustParseHexString parses s and returns the corresponding byte slice.
// It panics if the decoding fails.
func MustParseHexString(s string) []byte {
	// remove whitespace
	reg, err := regexp.Compile(`\s+`)
	if err != nil {
		panic(err)
	}
	s = reg.ReplaceAllString(s, "")

	decoded, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return decoded
}

// AssertReadReturnsBetween will call t.Fatalf if the first read from the
// channel doesn't happen between x and y.
func AssertReadReturnsBetween(t testing.TB, ch <-chan struct{}, x, y time.Duration) {
	AssertReadDoesNotReturnBefore(t, ch, x)
	// Above aborts the test if it returns before x time passed, so if we get
	// here x time has passed.
	AssertReadReturnsBefore(t, ch, y-x)
}

// AssertReadReturnsBefore will call t.Fatalf if the first read from the
// channel doesn't happen before timeout.
func AssertReadReturnsBefore(t testing.TB, ch <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("goroutine took too long to finish")
	}
}

// AssertReadDoesNotReturnBefore will call t.Fatalf if the first read from the
// channel happens before timeout.
func AssertReadDoesNotReturnBefore(t testing.TB, ch <-chan struct{}, timeout time.Duration) {
	select {
	case <-ch:
		t.Fatalf("goroutine finished too quickly")
	case <-time.After(timeout):
	}
}

// AssertError checks that err is not nil if expectError is true and that is it nil otherwise
func AssertError(t *testing.T, err error, expectError bool) {
	if expectError {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}
