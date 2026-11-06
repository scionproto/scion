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

package e2e

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v4"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/testing/clab/cmd/controller/config"
	"github.com/scionproto/scion/testing/clab/testgen/out"
)

// AS is one autonomous system: its ISD-AS, whether it is a core AS, and the
// control service segments-API URL.
type AS struct {
	IA          string
	Core        bool
	SegmentsURL string
}

// asList mirrors gen/as_list.yml.
type asList struct {
	Core    []string `yaml:"Core"`
	NonCore []string `yaml:"Non-core"`
}

// LoadASes discovers the ASes from the generated lab: their core/non-core
// grouping (gen/as_list.yml) and their control service API address
// (gen/[ISD<n>/]AS<file>/config.yml). The result is the list of ASes with their
// segments-API URL.
func LoadASes(genDir string) ([]AS, error) {
	raw, err := os.ReadFile(filepath.Join(genDir, "as_list.yml"))
	if err != nil {
		return nil, fmt.Errorf("reading as list: %w", err)
	}
	var list asList
	if err := yaml.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parsing as list: %w", err)
	}

	var ases []AS
	add := func(ia string, core bool) error {
		url, err := segmentsURL(genDir, ia)
		if err != nil {
			return err
		}
		ases = append(ases, AS{IA: ia, Core: core, SegmentsURL: url})
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
	return ases, nil
}

// segmentsURL returns the control service segments-API URL for an AS. It reads
// the prism config mirrored to the AS directory root (the config of the host
// running the control service) and extracts the control API address, the node's
// containerlab management address reachable from the host over the management
// bridge.
func segmentsURL(genDir, iaStr string) (string, error) {
	ia, err := addr.ParseIA(iaStr)
	if err != nil {
		return "", fmt.Errorf("parsing ISD-AS %q: %w", iaStr, err)
	}
	raw, err := readASConfig(genDir, ia)
	if err != nil {
		return "", err
	}
	cfg, err := config.DecodeYAML(raw)
	if err != nil {
		return "", fmt.Errorf("parsing config for %s: %w", ia, err)
	}
	for _, as := range cfg.SCION.ASes {
		if as.ISDAS != ia || as.Control == nil {
			continue
		}
		apiAddr := as.Control.APIAddr
		if !apiAddr.IsValid() {
			return "", fmt.Errorf("no control API address for %s", ia)
		}
		return fmt.Sprintf("http://%s/api/v1/segments", apiAddr), nil
	}
	return "", fmt.Errorf("no control service for %s in config", ia)
}

// readASConfig reads the control host's prism config mirrored to the AS
// directory root. testgen lays out the AS directories either flat
// (gen/ASff00_0_110) or grouped per ISD (gen/ISD1/ASff00_0_110, --isd-dir);
// both layouts are tried, flat first.
func readASConfig(genDir string, ia addr.IA) ([]byte, error) {
	var tried []string
	for _, isdDir := range []bool{false, true} {
		path := filepath.Join(out.New(genDir, isdDir).AS(ia), "config.yml")
		raw, err := os.ReadFile(path)
		if err == nil {
			return raw, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("reading config for %s: %w", ia, err)
		}
		tried = append(tried, path)
	}
	return nil, fmt.Errorf("no config for %s, tried: %s", ia, strings.Join(tried, ", "))
}
