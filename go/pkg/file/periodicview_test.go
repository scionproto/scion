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
	"encoding/pem"
	"flag"
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/pkg/file"
)

var (
	update = flag.Bool("update", false, "set to true to update reference testdata files")
)

const (
	// fileName points to the PEM test file used for both some tests and benchmarks. Only
	// the tests will update this file (if update is selected).
	fileName     = "testdata/key.pem"
	readInterval = 10 * time.Second
)

func TestPeriodicViewWithParser(t *testing.T) {
	key := []byte{
		0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
		4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
	}

	if *update {
		b, err := scrypto.EncodePEMSymmetricKey(key)
		require.NoError(t, err)
		err = ioutil.WriteFile(fileName, b, 0644)
		require.NoError(t, err)
	}

	view := &file.PeriodicView{
		ReadInterval: readInterval,
		Path:         fileName,
		Parser:       file.ParserFunc(pemKeyParse),
	}
	defer view.Close()

	newKey, err := view.Get()
	require.NoError(t, err)
	assert.Equal(t, key, newKey)
}

func TestPeriodicViewWithoutParser(t *testing.T) {
	f := "testdata/data.raw"
	b := []byte{1, 2, 3, 4}
	if *update {
		err := ioutil.WriteFile(f, b, 0644)
		require.NoError(t, err)
	}
	view := &file.PeriodicView{
		ReadInterval: readInterval,
		Path:         f,
	}
	defer view.Close()

	readB, err := view.Get()
	require.NoError(t, err)
	assert.Equal(t, b, readB)
}

func TestPeriodicViewTwoReaders(t *testing.T) {
	f := "testdata/two.raw"
	b := []byte{1, 2, 3, 4}
	if *update {
		err := ioutil.WriteFile(f, b, 0644)
		require.NoError(t, err)
	}
	viewOne := &file.PeriodicView{
		ReadInterval: readInterval,
		Path:         f,
	}
	defer viewOne.Close()
	viewTwo := &file.PeriodicView{
		ReadInterval: readInterval,
		Path:         f,
	}
	defer viewTwo.Close()

	readB, err := viewOne.Get()
	require.NoError(t, err)
	assert.Equal(t, b, readB)

	readB, err = viewTwo.Get()
	require.NoError(t, err)
	assert.Equal(t, b, readB)
}

func TestPeriodicViewGetAfterClose(t *testing.T) {
	view := &file.PeriodicView{
		ReadInterval: readInterval,
		Path:         fileName,
		Parser:       file.ParserFunc(pemKeyParse),
	}
	err := view.Close()
	require.NoError(t, err)
	_, err = view.Get()
	assert.Error(t, err)
}

func TestPeriodicViewMultipleReads(t *testing.T) {
	f := "testdata/multiple.raw"
	b := []byte{1, 2, 3, 4}
	if *update {
		err := ioutil.WriteFile(f, b, 0644)
		require.NoError(t, err)
	}
	view := &file.PeriodicView{
		ReadInterval: 10 * time.Millisecond,
		Path:         f,
	}
	defer view.Close()

	time.Sleep(200 * time.Millisecond)

	readB, err := view.Get()
	require.NoError(t, err)
	assert.Equal(t, b, readB)
}

func TestPeriodicViewNoFile(t *testing.T) {
	f := "testdata/nope.raw"
	view := &file.PeriodicView{
		ReadInterval: readInterval,
		Path:         f,
	}
	defer view.Close()

	_, err := view.Get()
	assert.Error(t, err)
}

func BenchmarkSyncFileView(b *testing.B) {
	view := &syncFileView{Path: fileName}
	benchmarkView(b, view)
}

// syncFileView implements a View that re-reads the file on every Get. This is
// included for benchmarking comparison purposes.
type syncFileView struct {
	Path string
}

func (v *syncFileView) Get() (interface{}, error) {
	b, err := ioutil.ReadFile(v.Path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	return block.Bytes, nil
}

func BenchmarkCachedFileView(b *testing.B) {
	view := &cachedFileView{
		view: &file.PeriodicView{
			ReadInterval: readInterval,
			Path:         fileName,
		},
	}
	benchmarkView(b, view)
}

// cachedFileView implements a View that only caches the contents of the file
// (without caching the result of the parser). This is included for benchmarking
// comparison purposes.
type cachedFileView struct {
	view *file.PeriodicView
}

func (v *cachedFileView) Get() (interface{}, error) {
	b, err := v.view.Get()
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b.([]byte))
	return block.Bytes, nil
}

func BenchmarkPeriodicView(b *testing.B) {
	view := &file.PeriodicView{
		ReadInterval: readInterval,
		Path:         fileName,
		Parser:       file.ParserFunc(pemKeyParse),
	}
	benchmarkView(b, view)
}

func benchmarkView(b *testing.B, view file.View) {
	for n := 0; n < b.N; n++ {
		_, err := view.Get()
		if err != nil {
			b.Fatalf("Error: %v", err)
		}
	}
}

func pemKeyParse(b []byte) (interface{}, error) {
	// Change the return type from []byte to interface{}
	return scrypto.ParsePEMSymmetricKey(b)
}
