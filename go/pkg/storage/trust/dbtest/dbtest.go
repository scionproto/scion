// Copyright 2020 Anapaya Systems
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

package dbtest

import (
	"context"
	"testing"

	"github.com/scionproto/scion/go/pkg/storage"
	"github.com/scionproto/scion/go/pkg/trust/dbtest"
)

// Config holds the configuration for the trust database testing harness.
type Config dbtest.Config

// TestableDB extends the trust db interface with methods that are needed for testing.
type TestableDB interface {
	storage.TrustDB
	// Prepare should reset the internal state so that the db is empty and is ready to be tested.
	Prepare(*testing.T, context.Context)
}

// Run should be used to test any implementation of the storage.TrustDB
// interface. An implementation interface should at least have one test method
// that calls this test-suite.
func Run(t *testing.T, db TestableDB, cfg Config) {
	c := dbtest.Config(cfg)
	if c.RelPath == "" {
		c.RelPath = "../../../trust/dbtest/testdata"
	}
	dbtest.Run(t, db, c)
}
