// Copyright 2020 ETH Zurich
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
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/drkey/specific"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	dkpb "github.com/scionproto/scion/pkg/proto/drkey"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/tools/integration"
)

// check just ensures the error is nil, or complains and quits
func check(e error) {
	if e != nil {
		panic(fmt.Sprintf("Fatal error: %v", e))
	}
}

type Client struct {
	daemon daemon.Connector
}

func NewClient(ctx context.Context, sciondPath string) Client {
	daemon, err := daemon.NewService(sciondPath).Connect(ctx)
	check(err)
	return Client{
		daemon: daemon,
	}
}

func (c Client) HostHostKey(ctx context.Context, meta drkey.HostHostMeta) drkey.HostHostKey {
	// get L2 key: (slow path)
	key, err := c.daemon.DRKeyGetHostHostKey(ctx, meta)
	check(err)
	return key
}

type Server struct {
	daemon daemon.Connector
}

func NewServer(ctx context.Context, sciondPath string) Server {
	daemon, err := daemon.NewService(sciondPath).Connect(ctx)
	check(err)
	return Server{
		daemon: daemon,
	}
}

// fetchSV obtains the Secret Value (SV) for the selected protocol/epoch.
// From this SV, all keys for this protocol/epoch can be derived locally.
// The IP address of the server must be explicitly allowed to abtain this SV
// from the the control server.
func (s Server) fetchSV(ctx context.Context, meta drkey.SecretValueMeta) drkey.SecretValue {
	// Obtain CS address from scion daemon
	svcs, err := s.daemon.SVCInfo(ctx, nil)
	check(err)
	cs := svcs[addr.SvcCS]
	if len(cs) == 0 {
		panic("no CS svc address")
	}

	// Contact CS directly for SV
	conn, err := grpc.DialContext(ctx, cs[0], grpc.WithInsecure())
	check(err)
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)

	rep, err := client.DRKeySecretValue(ctx, &cppb.DRKeySecretValueRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: dkpb.Protocol(meta.ProtoId),
	})
	check(err)
	key, err := getSecretFromReply(meta.ProtoId, rep)
	check(err)
	return key
}

func (s Server) HostHostKey(sv drkey.SecretValue, meta drkey.HostHostMeta) drkey.HostHostKey {
	var deriver specific.Deriver
	lvl1, err := deriver.DeriveLevel1(meta.DstIA, sv.Key)
	check(err)
	asHost, err := deriver.DeriveHostAS(meta.SrcHost, lvl1)
	check(err)
	hosthost, err := deriver.DeriveHostHost(meta.DstHost, asHost)
	check(err)
	return drkey.HostHostKey{
		ProtoId: sv.ProtoId,
		Epoch:   sv.Epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
		Key:     hosthost,
	}
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	var serverIA, clientIA addr.IA
	var serverIP, clientIP string

	flag.Var(&serverIA, "serverIA", "IA for the server-side IA.")
	flag.Var(&clientIA, "clientIA", "IA for the client-side IA.")
	flag.StringVar(&serverIP, "serverIP", "", "Server-host address.")
	flag.StringVar(&clientIP, "clientIP", "", "Client-host address.")
	flag.Parse()

	fmt.Println(serverIA)
	fmt.Println(clientIA)

	sciondForServer, err := integration.GetSCIONDAddress(
		integration.GenFile(integration.DaemonAddressesFile),
		serverIA,
	)
	check(err)
	sciondForClient, err := integration.GetSCIONDAddress(
		integration.GenFile(integration.DaemonAddressesFile),
		clientIA,
	)
	check(err)

	ctx, cancelF := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancelF()

	// meta describes the key that both client and server derive
	meta := drkey.HostHostMeta{
		ProtoId: drkey.SCMP,
		// Validity timestamp; both sides need to use the same time stamp when deriving the key
		// to ensure they derive keys for the same epoch.
		// Usually this is coordinated by means of a timestamp in the message.
		Validity: time.Now(),
		// SrcIA is the AS on the "fast side" of the DRKey derivation;
		// the server side in this example.
		SrcIA: serverIA,
		// DstIA is the AS on the "slow side" of the DRKey derivation;
		// the client side in this example.
		DstIA:   clientIA,
		SrcHost: serverIP,
		DstHost: clientIP,
	}

	// Client: fetch key from daemon
	// The daemon will in turn obtain the key from the local CS
	// The CS will fetch the Lvl1 key from the CS in the SrcIA (the server's AS)
	// and derive the Host key based on this.
	client := NewClient(ctx, sciondForClient)
	t0 := time.Now()
	clientKey := client.HostHostKey(ctx, meta)
	durationClient := time.Since(t0)
	fmt.Printf(
		"Client,\thost key = %s\tduration = %s\n",
		hex.EncodeToString(clientKey.Key[:]),
		durationClient,
	)

	// Server: get the Secret Value (SV) for the protocol and derive all subsequent keys in-process
	server := NewServer(ctx, sciondForServer)
	sv := server.fetchSV(ctx, drkey.SecretValueMeta{
		Validity: meta.Validity,
		ProtoId:  meta.ProtoId,
	})
	t0 = time.Now()
	serverKey := server.HostHostKey(sv, meta)
	durationServer := time.Since(t0)

	fmt.Printf(
		"Server,\thost key = %s\tduration = %s\n",
		hex.EncodeToString(serverKey.Key[:]),
		durationServer,
	)
	if clientKey.Key == serverKey.Key {
		return 0
	}
	return 1
}

func getSecretFromReply(
	proto drkey.Protocol,
	rep *cppb.DRKeySecretValueResponse,
) (drkey.SecretValue, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.SecretValue{}, err
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.SecretValue{}, err
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}
	returningKey := drkey.SecretValue{
		ProtoId: proto,
		Epoch:   epoch,
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}
