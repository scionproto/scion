// Copyright 2018 ETH Zurich
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

// Package integration provides function to simplify the creation of integration tests.
package integration

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/util"
)

type Integration interface {
	// Name returns the name of the test
	Name() string
	// StartServer should start the server listening on the address local.
	// StartServer should return immediately.
	// The context should be used to make the server cancellable.
	StartServer(ctx context.Context, local addr.IA) error
	// WaitServer should block until the server is terminated.
	// WaitServer should only be called after making sure that the server will stop,
	//  e.g. by cancelling the context.
	WaitServer() error
	// StartClient should start the client on the local address connecting to the remote address.
	// StartClient should return immediately.
	// The context should be used to make the client cancellable.
	StartClient(ctx context.Context, local, remote addr.IA) error
	// WaitClient should block until the client is terminated.
	WaitClient() error
}

// Init initializes the integration test, it adds and validates the command line flags.
func Init() error {
	addTestFlags()
	return validateFlags()
}

func addTestFlags() {
	log.AddLogConsFlags()
}

func validateFlags() error {
	flag.Parse()
	if err := log.SetupFromFlags(""); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		flag.Usage()
		return err
	}
	return nil
}

func LoadASList() (*util.ASList, error) {
	return util.LoadASList("gen/as_list.yml")
}

// Connection is a source, destination pair. The client (Src) will dial the server (Dst).
type Connection struct {
	Src addr.IA
	Dst addr.IA
}

// GenerateAllSrcDst generates the cartesian product shuffle(asList) x shuffle(asList).
func GenerateAllSrcDst(asList *util.ASList) []Connection {
	allAs := append(asList.Core, asList.NonCore...)
	allAs2 := append([]addr.IA(nil), allAs...)
	shuffle(len(allAs), func(i, j int) {
		allAs[i], allAs[j] = allAs[j], allAs[i]
		allAs2[i], allAs2[j] = allAs2[j], allAs2[i]
	})
	sd := make([]Connection, 0, len(allAs)*len(allAs2))
	for _, src := range allAs {
		for _, dst := range allAs2 {
			sd = append(sd, Connection{src, dst})
		}
	}
	return sd
}

// interface kept similar to go 1.10
func shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		swap(i, j)
	}
}

// RunTests runs the client and server for each connection.
// In case of an error the function is terminated immediately.
func RunTests(in Integration, connections []Connection) error {
	start := time.Now()

	// First run all servers
	dsts := extraceDsts(connections)
	for _, dst := range dsts {
		serverCtx, serverCancel := context.WithCancel(context.Background())
		defer serverCancel()
		err := in.StartServer(serverCtx, dst)
		if err != nil {
			return err
		}
	}

	// Now start the clients for srcDest pair
	for i, conn := range connections {
		log.Info(fmt.Sprintf("Test %v: %v -> %v (%v/%v)",
			in.Name(), conn.Src, conn.Dst, i, len(connections)))

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		err := in.StartClient(ctx, conn.Src, conn.Dst)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during start of the client: %s\n", err)
			return err
		}
		if err = in.WaitClient(); err != nil {
			fmt.Fprintf(os.Stderr, "Error during client execution: %s\n", err)
			return err
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("Test %v successful, used %v\n", in.Name(), elapsed)

	return nil
}

func extraceDsts(connections []Connection) []addr.IA {
	uniqueDsts := make(map[addr.IA]bool)
	for _, endp := range connections {
		if !uniqueDsts[endp.Dst] {
			uniqueDsts[endp.Dst] = true
		}
	}
	res := make([]addr.IA, 0, len(uniqueDsts))
	for dst := range uniqueDsts {
		res = append(res, dst)
	}
	return res
}
