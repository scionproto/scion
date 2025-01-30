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

// Package config provides an unified pattern for configuration structs.
//
// # Usage
//
// Every configuration struct should implement the Config interface. There
// are three parts to a configuration: Initialization, validation and
// sample generation.
//
// # Initialization
//
// A config struct is initialized by calling InitDefaults. This recursively
// initializes all uninitialized fields. Fields that should not be
// initialized to default must be set before calling InitDefaults.
//
// # Validation
//
// A config struct is validated by calling Validate. This recursively
// validates all fields.
//
// # Sample Generation
//
// A config struct can be used to generate a commented sample toml config
// by calling Sample. Unit tests guarantee the consistency between
// implementation and the generated sample. To this end, each config struct
// has to provide a composable unit test to check that the sample is
// parsable and consistent with the default values. See lib/envtest for an
// example.
//
// Warning: The method Sample is allowed to panic if an error occurs during
// sample generation.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/scionproto/scion/pkg/private/serrors"
)

const ID = "id"

// Config is the interface that config structs should implement to allow for
// streamlined initialization, validation and sample generation.
type Config interface {
	Sampler
	Validator
	Defaulter
}

// Validator defines the validation part of Config.
type Validator interface {
	// Validate recursively checks that all fields contain valid values.
	Validate() error
}

// Defaulter defines the initialization part of Config.
type Defaulter interface {
	// InitDefaults recursively initializes the default values of all
	// uninitialized fields.
	InitDefaults()
}

// Sampler defines the sample generation part of Config.
type Sampler interface {
	// Sample creates a sample config and writes it to dst. Ctx provides
	// additional information. Sample is allowed to panic if an error
	// occurs.
	Sample(dst io.Writer, path Path, ctx CtxMap)
}

// TableSampler is used to write a table to the sample.
type TableSampler interface {
	Sampler
	// ConfigName returns the name of the config block. This forces
	// consistency between samples for different services for the same
	// config block.
	ConfigName() string
}

// Path is the header of a config block possibly consisting of multiple parts.
type Path []string

// Extend creates a copy of the path with string s appended.
func (p Path) Extend(s string) Path {
	c := append(Path(nil), p...)
	return append(c, s)
}

// NoValidator implements a Validator that never fails to validate. It can
// be embedded in config structs that do not need to validate.
type NoValidator struct{}

// Validate always returns nil.
func (NoValidator) Validate() error {
	return nil
}

// NoDefaulter implements a Defaulter that does a no-op on InitDefaults.
// It can be embedded in config structs that do not have any defaults.
type NoDefaulter struct{}

// InitDefaults is a no-op.
func (NoDefaulter) InitDefaults() {}

// StringSampler implements a Sampler that writes string Text and provides
// Name as ConfigName.
type StringSampler struct {
	// Text the sample string.
	Text string
	// Name the config name.
	Name string
}

// Sample writes the text to dst.
func (s StringSampler) Sample(dst io.Writer, _ Path, _ CtxMap) {
	WriteString(dst, s.Text)
}

// ConfigName returns the name.
func (s StringSampler) ConfigName() string {
	return s.Name
}

// ValidateAll validates all validators. The first error encountered is returned.
func ValidateAll(validators ...Validator) error {
	for _, v := range validators {
		if err := v.Validate(); err != nil {
			return serrors.Wrap("Unable to validate", err, "type", fmt.Sprintf("%T", v))
		}
	}
	return nil
}

// InitAll initializes all defaulters.
func InitAll(defaulters ...Defaulter) {
	for _, v := range defaulters {
		v.InitDefaults()
	}
}

// Decode decodes a raw config.
func Decode(raw []byte, cfg any) error {
	return toml.NewDecoder(bytes.NewReader(raw)).DisallowUnknownFields().Decode(cfg)
}

// LoadFile loads the config from file.
func LoadFile(file string, cfg any) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	return Decode(raw, cfg)
}

type nameOverrideSampler struct {
	Sampler
	name string
}

func (s nameOverrideSampler) ConfigName() string {
	return s.name
}

// OverrideName creates a sampler that is identical to the one in the argument,
// except it will use the desired config name instead of the original one.
func OverrideName(s Sampler, name string) Sampler {
	return nameOverrideSampler{
		Sampler: s,
		name:    name,
	}
}

type formatDataSampler struct {
	Sampler
	data []any
}

func (s formatDataSampler) Sample(dst io.Writer, path Path, ctx CtxMap) {
	buf := &bytes.Buffer{}
	s.Sampler.Sample(buf, path, ctx)
	WriteString(dst, fmt.Sprintf(buf.String(), s.data...))
}

// FormatData creates a sampler that will call fmt.Sprintf on the string returned
// by s.Sample using the supplied argument information.
func FormatData(s Sampler, a ...any) Sampler {
	return formatDataSampler{
		Sampler: s,
		data:    a,
	}
}

// LoadResource returns an object suitable for reading based
// on the resource specified by location.
//
// If location starts with "http://" or "https://", LoadResource
// will issue an HTTP GET to retrieve the resource. Only the Body
// of the reply can be read from the returned reader.
//
// If the location does not start with "http://" or "https://,
// LoadResource interprets location as a file path and loads the resource
// from disk.
//
// It is the caller's responsibility to close the returned reader.
func LoadResource(location string) (io.ReadCloser, error) {
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		response, err := http.Get(location)
		if err != nil {
			return nil, serrors.Wrap("fetching config over HTTP", err)
		}

		return response.Body, nil
	}
	rc, err := os.Open(location)
	if err != nil {
		return nil, serrors.Wrap("loading config from disk", err)
	}
	return rc, nil
}

// Digest calculates a digest of the configuration by attempting to encode the configuration as
// JSON object and then calculate the SHA256 sum on the resulting encoding.
func Digest(cfg Config) ([]byte, error) {
	h := sha256.New()
	enc := json.NewEncoder(h)
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
