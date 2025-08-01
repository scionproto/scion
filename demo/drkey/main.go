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
	"fmt"
	"os"
	"time"

	flag "github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/drkey/generic"
	"github.com/scionproto/scion/pkg/drkey/specific"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	dkpb "github.com/scionproto/scion/pkg/proto/drkey"
	"github.com/scionproto/scion/pkg/snet"
	env "github.com/scionproto/scion/private/app/flag"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	var serverMode bool
	var serverAddrStr, clientAddrStr string
	var protocol uint16
	var fetchSV bool
	var scionEnv env.SCIONEnvironment

	scionEnv.Register(flag.CommandLine)
	flag.BoolVar(&serverMode, "server", false, "Demonstrate server-side key derivation."+
		" (default demonstrate client-side key fetching)")
	flag.StringVar(&serverAddrStr, "server-addr", "", "SCION address for the server-side.")
	flag.StringVar(&clientAddrStr, "client-addr", "", "SCION address for the client-side.")
	flag.Uint16Var(&protocol, "protocol", 1 /* SCMP */, "DRKey protocol identifier.")
	flag.BoolVar(&fetchSV, "fetch-sv", false,
		"Fetch protocol specific secret value to derive server-side keys.")
	flag.Parse()
	if err := scionEnv.LoadExternalVars(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading SCION environment:", err)
		return 2
	}

	// NOTE: should parse addresses as snet.SCIONAddress not snet.UDPAddress, but
	// these parsing functions don't exist yet.
	serverAddr, err := snet.ParseUDPAddr(serverAddrStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid --server-addr '%s': %s\n", serverAddrStr, err)
		return 2
	}
	clientAddr, err := snet.ParseUDPAddr(clientAddrStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid --client-addr '%s': %s\n", clientAddrStr, err)
		return 2
	}

	if !serverMode && fetchSV {
		fmt.Fprintf(os.Stderr, "Invalid flag --fetch-sv for client-side key derivation\n")
		return 2
	}

	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// meta describes the key that both client and server derive
	meta := drkey.HostHostMeta{
		ProtoId: drkey.Protocol(protocol),
		// Validity timestamp; both sides need to use a validity time stamp in the same epoch.
		// Usually this is coordinated by means of a timestamp in the message.
		Validity: time.Now(),
		// SrcIA is the AS on the "fast side" of the DRKey derivation;
		// the server side in this example.
		SrcIA: serverAddr.IA,
		// DstIA is the AS on the "slow side" of the DRKey derivation;
		// the client side in this example.
		DstIA:   clientAddr.IA,
		SrcHost: serverAddr.Host.IP.String(),
		DstHost: clientAddr.Host.IP.String(),
	}

	daemon, err := daemon.NewService(scionEnv.Daemon()).Connect(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error dialing SCION Daemon:", err)
		return 1
	}

	if serverMode {
		// Server: get the Secret Value (SV) for the protocol and derive all
		// subsequent keys in-process
		server := Server{daemon}
		var serverKey drkey.HostHostKey
		var t0, t1, t2 time.Time
		if fetchSV {
			// Fetch the Secret Value (SV); in a real application, this is only done at
			// startup and refreshed for each epoch.
			t0 = time.Now()
			sv, err := server.FetchSV(ctx, drkey.SecretValueMeta{
				ProtoId:  meta.ProtoId,
				Validity: meta.Validity,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error fetching secret value:", err)
				return 1
			}
			t1 = time.Now()
			serverKey, err = server.DeriveHostHostKeySpecific(sv, meta)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error deriving key:", err)
				return 1
			}
			t2 = time.Now()
		} else {
			// Fetch host-AS key (Level 2). This key can be used to derive keys for
			// all hosts in the destination AS. Depending on the application, it can
			// be cached and refreshed for each epoch.
			t0 = time.Now()
			hostASKey, err := server.FetchHostASKey(ctx, drkey.HostASMeta{
				ProtoId:  meta.ProtoId,
				Validity: meta.Validity,
				SrcIA:    meta.SrcIA,
				DstIA:    meta.DstIA,
				SrcHost:  meta.SrcHost,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error fetching host-AS key:", err)
				return 1
			}
			t1 = time.Now()
			serverKey, err = server.DeriveHostHostKeyGeneric(hostASKey, meta)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error deriving key:", err)
				return 1
			}
			t2 = time.Now()
		}
		fmt.Printf(
			"Server: host key = %s, protocol = %s, fetch-sv = %v"+
				"\n\tduration without cache: %s\n\tduration with cache: %s"+
				"\n\tserver: %s\n\tclient: %s\n",
			hex.EncodeToString(serverKey.Key[:]), meta.ProtoId, fetchSV, t2.Sub(t0), t2.Sub(t1),
			serverAddr, clientAddr,
		)
	} else {
		// Client: fetch key from daemon
		// The daemon will in turn obtain the key from the local CS
		// The CS will fetch the Lvl1 key from the CS in the SrcIA (the server's AS)
		// and derive the Host key based on this.
		client := Client{daemon}
		var t0, t1 time.Time
		t0 = time.Now()
		clientKey, err := client.FetchHostHostKey(ctx, meta)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error fetching key:", err)
			return 1
		}
		t1 = time.Now()

		fmt.Printf(
			"Client: host key = %s, protocol = %s\n\tduration: %s\n"+
				"\n\tserver: %s\n\tclient: %s\n",
			hex.EncodeToString(clientKey.Key[:]), meta.ProtoId, t1.Sub(t0),
			serverAddr, clientAddr,
		)
	}
	return 0
}

type Client struct {
	daemon daemon.Connector
}

func (c Client) FetchHostHostKey(
	ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error) {

	// get level 3 key: (slow path)
	return c.daemon.DRKeyGetHostHostKey(ctx, meta)
}

type Server struct {
	daemon daemon.Connector
}

func (s Server) DeriveHostHostKeySpecific(
	sv drkey.SecretValue,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {

	var deriver specific.Deriver
	lvl1, err := deriver.DeriveLevel1(meta.DstIA, sv.Key)
	if err != nil {
		return drkey.HostHostKey{}, serrors.Wrap("deriving level 1 key", err)
	}
	asHost, err := deriver.DeriveHostAS(meta.SrcHost, lvl1)
	if err != nil {
		return drkey.HostHostKey{}, serrors.Wrap("deriving host-AS key", err)
	}
	hosthost, err := deriver.DeriveHostHost(meta.DstHost, asHost)
	if err != nil {
		return drkey.HostHostKey{}, serrors.Wrap("deriving host-host key", err)
	}
	return drkey.HostHostKey{
		ProtoId: sv.ProtoId,
		Epoch:   sv.Epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
		Key:     hosthost,
	}, nil
}

func (s Server) DeriveHostHostKeyGeneric(
	hostAS drkey.HostASKey,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {

	deriver := generic.Deriver{
		Proto: hostAS.ProtoId,
	}
	hosthost, err := deriver.DeriveHostHost(meta.DstHost, hostAS.Key)
	if err != nil {
		return drkey.HostHostKey{}, serrors.Wrap("deriving host-host key", err)
	}
	return drkey.HostHostKey{
		ProtoId: hostAS.ProtoId,
		Epoch:   hostAS.Epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
		Key:     hosthost,
	}, nil
}

// FetchSV obtains the Secret Value (SV) for the selected protocol/epoch.
// From this SV, all keys for this protocol/epoch can be derived locally.
// The IP address of the server must be explicitly allowed to abtain this SV
// from the the control server.
func (s Server) FetchSV(
	ctx context.Context,
	meta drkey.SecretValueMeta,
) (drkey.SecretValue, error) {

	// Obtain CS address from scion daemon
	svcs, err := s.daemon.SVCInfo(ctx, nil)
	if err != nil {
		return drkey.SecretValue{}, serrors.Wrap("obtaining control service address", err)
	}
	cs := svcs[addr.SvcCS]
	if len(cs) == 0 {
		return drkey.SecretValue{}, serrors.New("no control service address found")
	}

	// Contact CS directly for SV
	//nolint:staticcheck // ignore SA1019; Support remains in 1.x; we won't use v2.
	conn, err := grpc.DialContext(
		ctx, cs[0], grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return drkey.SecretValue{}, serrors.Wrap("dialing control service", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)

	rep, err := client.DRKeySecretValue(ctx, &cppb.DRKeySecretValueRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: dkpb.Protocol(meta.ProtoId),
	})
	if err != nil {
		return drkey.SecretValue{}, serrors.Wrap("requesting drkey secret value", err)
	}

	key, err := getSecretFromReply(meta.ProtoId, rep)
	if err != nil {
		return drkey.SecretValue{}, serrors.Wrap("validating drkey secret value reply", err)
	}

	return key, nil
}

func getSecretFromReply(
	proto drkey.Protocol,
	rep *cppb.DRKeySecretValueResponse,
) (drkey.SecretValue, error) {

	if err := rep.EpochBegin.CheckValid(); err != nil {
		return drkey.SecretValue{}, err
	}
	if err := rep.EpochEnd.CheckValid(); err != nil {
		return drkey.SecretValue{}, err
	}
	epoch := drkey.Epoch{
		NotBefore: rep.EpochBegin.AsTime(),
		NotAfter:  rep.EpochEnd.AsTime(),
	}
	returningKey := drkey.SecretValue{
		ProtoId: proto,
		Epoch:   epoch,
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

func (s Server) FetchHostASKey(
	ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error) {

	// get level 2 key: (fast path)
	return s.daemon.DRKeyGetHostASKey(ctx, meta)
}
