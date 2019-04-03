// Copyright 2019 ETH Zurich
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

package parser

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	golayers "github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
)

type propMap map[string]string

func getKeyValueMap(line string) propMap {
	if line == "" {
		return nil
	}
	line = strings.TrimSpace(line)
	// replace more than one contiguous space for single space
	line = regexp.MustCompile(` {2,}`).ReplaceAllString(line, " ")
	// validate that the line has expected format: spaced separated list of key/value pairs
	valid := regexp.MustCompile(`^\w+=\S+( \w+=\S+)*$`).FindString(line)
	if valid == "" {
		panic(fmt.Errorf("Invalid Key/Value pair syntax '%s'", line))
	}
	parts := strings.Split(line, " ")
	kvs := make(propMap)
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		kvs[kv[0]] = kv[1]
	}
	return kvs
}

func ParseProto(enumMeta []golayers.EnumMetadata, protoName string) uint {
	for i := 0; i < len(enumMeta); i++ {
		if enumMeta[i].Name == protoName {
			return uint(i)
		}
	}
	panic(fmt.Errorf("Protocol name '%s' not found", protoName))
}

func StrToInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("StrToInt error converting '%s'\n", s))
	}
	return i
}

func HexToInt(s string) uint {
	i, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		panic(fmt.Sprintf("HexToInt error converting '%s'\n", s))
	}
	return uint(i)
}

func HexToBytes(s string) common.RawBytes {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("HexToBytes error converting '%s'\n", b))
	}
	return b
}

func StrToBool(s string) bool {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	}
	panic(fmt.Sprintf("StrToBool error converting '%s'\n", s))
}
