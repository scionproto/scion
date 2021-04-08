// Copyright 2019 Anapaya Systems
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

// Package config contains building blocks for CA functionality configuration.
package config

import (
	"time"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/pkg/file"
)

const (
	// DefaultReadInterval is periodic interval for reading files again from disk.
	DefaultReadInterval = 5 * time.Second
)

// PEMSymmetricKey is a key that is kept in sync with the PEM-encoded version on disk.
// The synchronization delay is subject to DefaultReadInterval.
type PEMSymmetricKey struct {
	secret file.View
}

func (s *PEMSymmetricKey) Get() ([]byte, error) {
	o, err := s.secret.Get()
	if err != nil {
		return nil, err
	}
	return o.([]byte), nil
}

// NewPEMSymmetricKey returns an object that can be queried to load the
// PEM-encoded symmetric key located at path. The returned key will be kept up
// to date with the disk (with a maximum delay based on DefaultReadInterval).
//
// The returned object will consume resources for the lifetime of the application.
func NewPEMSymmetricKey(path string) *PEMSymmetricKey {
	return &PEMSymmetricKey{
		secret: &file.PeriodicView{
			ReadInterval: DefaultReadInterval,
			Path:         path,
			Parser:       file.ParserFunc(parsePEMSymmetricKey),
		},
	}
}

func parsePEMSymmetricKey(b []byte) (interface{}, error) {
	return scrypto.ParsePEMSymmetricKey(b)
}
