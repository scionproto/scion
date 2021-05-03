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
	"path/filepath"
	"strings"

	"github.com/scionproto/scion/go/lib/serrors"
)

// Option is the type to add optional behavior changes.
type Option func(o *options)

type options struct {
	backupPattern string
	force         bool
}

// WithBackup specifies the backup pattern for backing up files that already
// exist. If the filename has an extension, the pattern is inserted between
// filename base and extension. If the filename does not have an extension, the
// pattern is added as a suffix.
//
// WithBackup takes precedence over WithForce, meaning, if a file exists, it
// is backed up and not overwritten.
//
// Example: (pattern: 2021-05-06)
// - example.txt -> example.2021-05-06.txt
// - example     -> example.2021-05-06
func WithBackup(pattern string) Option {
	return func(o *options) {
		o.backupPattern = pattern
	}
}

// WithForce specifies whether a file should be overwritten if it already exists.
//
// WithBackup takes precedence over WithForce, meaning, if a file exists, it
// is backed up and not overwritten.
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

// WriteFile writes the supplied data to the file.
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

	switch {
	case options.backupPattern != "":
		ext := filepath.Ext(filename)
		backup := strings.TrimSuffix(filename, ext) + "." + options.backupPattern + ext
		if err := os.Rename(filename, backup); err != nil {
			return serrors.WrapStr("backing up file", err)
		}
	case options.force:
		if err := os.Remove(filename); err != nil {
			return serrors.WrapStr("removing existing file", err)
		}
	default:
		return os.ErrExist
	}

	return ioutil.WriteFile(filename, data, perm)
}
