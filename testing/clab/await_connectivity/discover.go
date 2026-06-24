// Copyright 2026 Anapaya Systems
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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// as is one autonomous system: its ISD-AS, whether it is a core AS, and the
// control service segments-API URL.
type as struct {
	IA          string
	Core        bool
	SegmentsURL string
}

// asList mirrors gen/as_list.yml.
type asList struct {
	Core    []string `yaml:"Core"`
	NonCore []string `yaml:"Non-core"`
}

// controlConfig is the subset of a control service TOML we need: its API
// address. testgen mirrors the cs*.toml to the AS directory root and the
// address is the node's containerlab management address, reachable from the
// host over the management bridge.
type controlConfig struct {
	API struct {
		Addr string `toml:"addr"`
	} `toml:"api"`
}

// loadASes discovers the ASes from the generated lab: their core/non-core
// grouping (gen/as_list.yml) and their control service API address
// (gen/AS<file>/cs*.toml). The result is the list of ASes with their
// segments-API URL.
func loadASes(genDir string) ([]as, error) {
	raw, err := os.ReadFile(filepath.Join(genDir, "as_list.yml"))
	if err != nil {
		return nil, fmt.Errorf("reading as list: %w", err)
	}
	var list asList
	if err := yaml.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parsing as list: %w", err)
	}

	var out []as
	add := func(ia string, core bool) error {
		url, err := segmentsURL(genDir, ia)
		if err != nil {
			return err
		}
		out = append(out, as{IA: ia, Core: core, SegmentsURL: url})
		return nil
	}
	for _, ia := range list.Core {
		if err := add(ia, true); err != nil {
			return nil, err
		}
	}
	for _, ia := range list.NonCore {
		if err := add(ia, false); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// segmentsURL returns the control service segments-API URL for an AS.
func segmentsURL(genDir, ia string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(asDir(genDir, ia), "cs*.toml"))
	if err != nil || len(matches) == 0 {
		return "", fmt.Errorf("no control config for %s in %s", ia, asDir(genDir, ia))
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		return "", fmt.Errorf("reading control config for %s: %w", ia, err)
	}
	var cfg controlConfig
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return "", fmt.Errorf("parsing control config for %s: %w", ia, err)
	}
	if cfg.API.Addr == "" {
		return "", fmt.Errorf("no control API address for %s", ia)
	}
	return fmt.Sprintf("http://%s/api/v1/segments", cfg.API.Addr), nil
}

// asDir returns the gen directory of an AS, e.g. gen/ASff00_0_110.
func asDir(genDir, ia string) string {
	asPart := ia[strings.IndexByte(ia, '-')+1:]
	return filepath.Join(genDir, "AS"+strings.ReplaceAll(asPart, ":", "_"))
}
