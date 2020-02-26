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

package log_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/log"
)

func TestLoggerCtxEmbedding(t *testing.T) {
	t.Run("Given a context with no logger attached", func(t *testing.T) {
		ctx, cancelF := context.WithCancel(context.Background())
		defer cancelF()
		t.Run("Extracting the logger yields a non-nil logger", func(t *testing.T) {
			logger := log.FromCtx(ctx)
			assert.NotNil(t, logger)
		})
	})
	t.Run("Given a context with a logger attached", func(t *testing.T) {
		logger := log.Root().New()
		ctx := log.CtxWith(context.Background(), logger)
		t.Run("Extracting the logger returns the correct object", func(t *testing.T) {
			extractedLogger := log.FromCtx(ctx)
			assert.Equal(t, logger, extractedLogger)
		})
	})
}
