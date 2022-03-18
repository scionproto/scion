// Copyright 2020 Anapaya Systems
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

package fuzz

import (
	"testing"
)

// This file contains convenience functions for debugging crashers.
// Replace the 'replace-me' with the quoted crasher
// and debug the panicking test.

func TestFuzzSCION(t *testing.T) {
	data := []byte("replace-me")
	FuzzSCION(data)
}

func TestFuzzHopByHopExtn(t *testing.T) {
	data := []byte("replace-me")
	FuzzHopByHopExtn(data)
}

func TestFuzzEndToEndExtn(t *testing.T) {
	data := []byte("replace-me")
	FuzzEndToEndExtn(data)
}

func TestFuzzUDP(t *testing.T) {
	data := []byte("replace-me")
	FuzzUDP(data)
}

func TestFuzzSCMP(t *testing.T) {
	data := []byte("replace-me")
	FuzzSCMP(data)
}

func TestFuzzSCMPEcho(t *testing.T) {
	data := []byte("replace-me")
	FuzzSCMPEcho(data)
}

func TestFuzzSCMPTraceroute(t *testing.T) {
	data := []byte("replace-me")
	FuzzSCMPTraceroute(data)
}

func TestFuzzSCMPExternalInterfaceDown(t *testing.T) {
	data := []byte("replace-me")
	FuzzSCMPExternalInterfaceDown(data)
}

func TestFuzzSCMPInternalConnectivityDown(t *testing.T) {
	data := []byte("replace-me")
	FuzzSCMPInternalConnectivityDown(data)
}
