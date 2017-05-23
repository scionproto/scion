// Copyright 2017 ETH Zurich
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

package integration

import (
	"testing"
	"fmt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

func SubtestPaths(t *testing.T, connector *sciond.Connector) {
	srcIA, _ := addr.IAFromString("0-0")
	dstIA, _ := addr.IAFromString("1-12")
	_, err := connector.Paths(srcIA, dstIA, 5, false, false)
	
	if err != nil {
		t.Fatalf("Error: %v.", err)
	}
}

func SubtestASInfo(t *testing.T, connector *sciond.Connector) {
	ia, _ := addr.IAFromString("1-12")
	_, err := connector.ASInfo(ia)

	if err != nil {
		t.Fatalf("Error: %v.", err)
	}
}
	
func SubtestIFInfo(t *testing.T, connector *sciond.Connector) {
	testCases := [][]uint64{
		{51, 93, 3, 4},
		{51, 93, 3, 4},
		{51, 93, 1, 51},
		{7, 8, 9, 10}}
	
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v", tc), func(t *testing.T) {
			_, err := connector.IFInfo(tc)

			if err != nil {
				t.Fatal("Error: %v.", err)
			}
		})
	}
}

func SubtestSVCInfo(t *testing.T, connector *sciond.Connector) {
	testCases := [][]addr.HostSVC{
		{addr.SvcBS},
		{addr.SvcPS},
		{addr.SvcCS},
		{addr.HostSVC(4)},
		{addr.SvcPS, addr.SvcCS}}
	
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v", tc), func(t *testing.T) {
			_, err := connector.SVCInfo(tc)

			if err != nil {
				t.Fatal("Error: %s.", err)
			}
		})
	}
}

func TestASInfo(t *testing.T) {
	connector, err := sciond.Connect("/run/shm/sciond/sd1-10.sock")
	if err != nil {
		t.Fatalf("Error: %v.", err)
	}

	t.Run("ASInfo", func(t *testing.T) {SubtestASInfo(t, connector)})
	t.Run("ASInfo cache", func(t *testing.T) {SubtestASInfo(t, connector)})
	t.Run("Paths", func(t *testing.T) {SubtestPaths(t, connector)})
	t.Run("IFs", func(t *testing.T) {SubtestIFInfo(t, connector)})
	t.Run("SVCs", func(t *testing.T) {SubtestSVCInfo(t, connector)})
	
	err = connector.Close()
	if err != nil {
		t.Fatalf("Error: %v.", err)
	}
}
