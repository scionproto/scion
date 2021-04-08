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

package file

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"sync"
)

// readTask is a periodic Task implementation (from the periodic package) that
// reads binary file contents.
type readTask struct {
	// Path of the file to read.
	Path string

	mu sync.Mutex
	// data contains the bytes of the last read.
	data []byte
	// err contains the error result of the last read.
	err error
	// changed is set to true whenever the data or error from a read differs
	// with the previous known state. Changed is set to false on every Snapshot
	// call.
	changed bool
}

func (t *readTask) Run(ctx context.Context) {
	t.read()
}

func (t *readTask) Name() string {
	return "anapaya_go_pkg_file_read"
}

func (t *readTask) read() {
	b, err := ioutil.ReadFile(t.Path)

	t.mu.Lock()
	defer t.mu.Unlock()

	if !bytes.Equal(b, t.data) {
		t.changed = true
	}
	if fmt.Sprint(err) != fmt.Sprint(t.err) {
		t.changed = true
	}
	t.data = b
	t.err = err
}

// Snapshot returns the results of the last file read. If the file contents have
// changed since the last call to Snapshot, the returned boolean is set to true.
//
// Snapshot can be called concurrently by multiple goroutines. However, the
// goroutines need to coordinate on how to manage the returned boolean value.
func (t *readTask) Snapshot() ([]byte, error, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	wasChanged := t.changed
	t.changed = false
	return t.data, t.err, wasChanged
}
