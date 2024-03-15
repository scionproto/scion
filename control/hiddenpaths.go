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

package control

import (
	"google.golang.org/grpc"

	beaconinggrpc "github.com/scionproto/scion/control/beaconing/grpc"
	"github.com/scionproto/scion/control/segreq"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	hpgrpc "github.com/scionproto/scion/pkg/experimental/hiddenpath/grpc"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	hspb "github.com/scionproto/scion/pkg/proto/hidden_segment"
	"github.com/scionproto/scion/private/pathdb"
	infra "github.com/scionproto/scion/private/segment/verifier"
)

// HiddenPathConfigurator can be used to configure the hidden path servers.
type HiddenPathConfigurator struct {
	LocalIA           addr.IA
	Verifier          infra.Verifier
	Signer            hpgrpc.Signer
	PathDB            pathdb.DB
	Dialer            libgrpc.Dialer
	FetcherConfig     segreq.FetcherConfig
	IntraASTCPServer  *grpc.Server
	InterASQUICServer *grpc.Server
}

// Setup sets up the hidden paths servers using the configuration at the given
// location. An empty location will not enable any hidden path behavior. It
// returns the configuration for the hidden segment writer. The return value can
// be nil if this AS isn't a writer.
func (c HiddenPathConfigurator) Setup(location string) (*HiddenPathRegistrationCfg, error) {
	if location == "" {
		return nil, nil
	}
	groups, regPolicy, err := hiddenpath.LoadConfiguration(location)
	if err != nil {
		return nil, err
	}
	roles := groups.Roles(c.LocalIA)
	if roles.None() {
		return nil, nil
	}
	log.Info("Starting hidden path forward server")
	hspb.RegisterHiddenSegmentLookupServiceServer(c.IntraASTCPServer, &hpgrpc.SegmentServer{
		Lookup: hiddenpath.ForwardServer{
			Groups:    groups,
			LocalAuth: c.localAuthServer(groups),
			LocalIA:   c.LocalIA,
			RPC: &hpgrpc.AuthoritativeRequester{
				Dialer: c.Dialer,
				Signer: c.Signer,
			},
			Resolver: hiddenpath.LookupResolver{
				Router: segreq.NewRouter(c.FetcherConfig),
				Discoverer: &hpgrpc.Discoverer{
					Dialer: c.Dialer,
				},
			},
			Verifier: hiddenpath.VerifierAdapter{
				Verifier: c.Verifier,
			},
		},
	})
	if roles.Registry {
		log.Info("Starting hidden path authoritative and registration server")
		hspb.RegisterAuthoritativeHiddenSegmentLookupServiceServer(c.InterASQUICServer,
			&hpgrpc.AuthoritativeSegmentServer{
				Lookup:   c.localAuthServer(groups),
				Verifier: c.Verifier,
			},
		)
		hspb.RegisterHiddenSegmentRegistrationServiceServer(c.InterASQUICServer,
			&hpgrpc.RegistrationServer{
				Registry: hiddenpath.RegistryServer{
					Groups: groups,
					DB: &hiddenpath.Storer{
						DB: c.PathDB,
					},
					Verifier: hiddenpath.VerifierAdapter{
						Verifier: c.Verifier,
					},
					LocalIA: c.LocalIA,
				},
				Verifier: c.Verifier,
			},
		)
	}
	if !roles.Writer {
		return nil, nil
	}
	log.Info("Using hidden path beacon writer")
	return &HiddenPathRegistrationCfg{
		Policy: regPolicy,
		Router: segreq.NewRouter(c.FetcherConfig),
		Discoverer: &hpgrpc.Discoverer{
			Dialer: c.Dialer,
		},
		RPC: &hpgrpc.Registerer{
			Dialer:              c.Dialer,
			RegularRegistration: beaconinggrpc.Registrar{Dialer: c.Dialer},
			Signer:              c.Signer,
		},
	}, nil
}

func (c HiddenPathConfigurator) localAuthServer(groups hiddenpath.Groups) hiddenpath.Lookuper {
	roles := groups.Roles(c.LocalIA)
	if !roles.Registry {
		return nil
	}
	return hiddenpath.AuthoritativeServer{
		Groups: groups,
		DB: &hiddenpath.Storer{
			DB: c.PathDB,
		},
		LocalIA: c.LocalIA,
	}
}
