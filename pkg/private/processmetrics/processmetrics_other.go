// Copyright 2023 SCION Association
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

// Package processmetrics provides a custom collector to export process-level
// metrics beyond what prometheus.ProcesssCollector offers.
// This is the generic implementation. It does nothing.

//go:build !linux

package processmetrics

import (
	"github.com/scionproto/scion/pkg/private/serrors"
)

func Init() error {
	return serrors.New("Not supported for this platform")
}
