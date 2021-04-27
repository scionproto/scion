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

// Package file contains helper functions to interact with files.
package file

import (
	"errors"
	"io/ioutil"
	"os"

	"github.com/scionproto/scion/go/lib/serrors"
)

// Option is the type to add optional behavior changes.
type Option func(o *options)

type options struct {
	force bool
}

// WithForce overwrites an existing file if it already exists.
func WithForce(force bool) Option {
	return func(o *options) {
		o.force = force
	}
}

func apply(opts []Option) options {
	var o options
	for _, option := range opts {
		option(&o)
	}
	return o
}

// CheckDirExists checks that whether the provided directory exists.
func CheckDirExists(dir string) error {
	stat, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return serrors.New("directory does not exist")
	}
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return serrors.New("not a directory")
	}
	return nil
}

func WriteFile(filename string, data []byte, perm os.FileMode, opts ...Option) error {
	options := apply(opts)

	info, err := os.Stat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return ioutil.WriteFile(filename, data, perm)
	}
	if err != nil {
		return serrors.WrapStr("reading stat information", err)
	}
	if info.IsDir() {
		return serrors.New("file is a directory")
	}
	if !options.force {
		return os.ErrExist
	}
	if err := os.Remove(filename); err != nil {
		return serrors.WrapStr("removing existing file", err)
	}
	return ioutil.WriteFile(filename, data, perm)
}
