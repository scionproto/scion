// Copyright 2018 Anapaya Systems
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
	"bytes"
	"go/format"
	"io/ioutil"
	"os"

	yaml "gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

const (
	// DfltIface is the letter that represents the default interface in names.
	DfltIface = "X"
)

type topo struct {
	ASes  yaml.MapSlice `yaml:"ASes"`
	Links []link
}

func loadTopo(topoFile string) (*topo, error) {
	buffer, err := ioutil.ReadFile(topoFile)
	if err != nil {
		return nil, common.NewBasicError("Unable to read from file", err, "name", topoFile)
	}
	var t topo
	err = yaml.Unmarshal(buffer, &t)
	if err != nil {
		return nil, common.NewBasicError("Unable to parse YAML data", err)
	}
	return &t, nil
}

func LoadGraph(topoFile string) (*Graph, error) {
	t, err := loadTopo(topoFile)
	if err != nil {
		return nil, common.NewBasicError("Failed to load Topo", err)
	}
	return newGraph(t.Links, graph.StaticIfaceIdMapping), nil
}

// WriteGraphToFile writes the default graph from topoFile to the destFile.
func WriteGraphToFile(topoFile, destFile string) error {
	g, err := LoadGraph(topoFile)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	_, err = g.Write(&buf)
	if err != nil {
		return common.NewBasicError("Failed to write graph to byte buffer", err)
	}
	fmtCode, err := format.Source(buf.Bytes())
	if err != nil {
		return common.NewBasicError("Failed to fmt code", err)
	}
	return ioutil.WriteFile(destFile, fmtCode, os.ModePerm)
}
