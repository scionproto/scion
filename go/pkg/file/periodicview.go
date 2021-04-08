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
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/serrors"
)

// PeriodicView is a View implementation that periodically re-reads file contents
// from disk and then parses them into an object.
//
// To free up resources used by the PeriodicView, call Close. Calling Get after Close
// will return an error.
//
// It is not safe to change PeriodicView fields after the first call to Get.
type PeriodicView struct {
	// ReadInterval is the duration between re-reads from disk.
	ReadInterval time.Duration

	// Path to the file to read.
	Path string

	// Parser is used to construct the cached object whenever the View re-reads different
	// contents from the file. If nil, the object isn't parsed and the bytes are returned
	// as-is.
	Parser Parser

	mu         sync.Mutex
	readTask   *readTask
	taskRunner *periodic.Runner
	running    bool
	closed     bool
	obj        interface{}
	err        error
}

// Parser converts a slice of bytes into an object.
type Parser interface {
	Parse(b []byte) (interface{}, error)
}

// ParserFunc is a convenience type for using typical Go parsers as the Parser
// type in this package.
type ParserFunc func(b []byte) (interface{}, error)

func (f ParserFunc) Parse(b []byte) (interface{}, error) {
	return f(b)
}

func (v *PeriodicView) Get() (interface{}, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return nil, serrors.New("view was closed")
	}

	if !v.running {
		// Do the first file read in the current goroutine, to ensure that the first
		// Get doesn't have to race with the first execution of the periodic runner for
		// data to be available.
		v.readTask = &readTask{Path: v.Path}
		v.readTask.read()

		// Launch goroutine for future reads.
		v.taskRunner = periodic.Start(v.readTask, v.ReadInterval, v.ReadInterval)
		v.running = true
	}

	b, err, changed := v.readTask.Snapshot()
	if err != nil {
		// If we are unable to read from the file, always return an error.
		// This allows the caller to react to the error.
		v.err = err
		v.obj = nil
	} else if changed {
		obj, err := v.invokeParserLocked(b)
		v.obj = obj
		v.err = err
	}
	return v.obj, v.err
}

func (v *PeriodicView) invokeParserLocked(b []byte) (interface{}, error) {
	if v.Parser == nil {
		return b, nil
	}
	return v.Parser.Parse(b)
}

// Close cleans up the internal resources used to maintain the PeriodicView.
//
// Calling Close more than once is a no-op.
func (v *PeriodicView) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.closed && v.running {
		v.taskRunner.Stop()
	}
	v.closed = true
	return nil
}
