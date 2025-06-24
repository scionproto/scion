// Copyright 2025 Anapaya Systems
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

package registration

import (
	"context"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet/addrutil"
)

// DefaultSegmentRegistrationPlugin is the default registration plugin.
type DefaultSegmentRegistrationPlugin struct{}

var _ SegmentRegistrationPlugin = (*DefaultSegmentRegistrationPlugin)(nil)

func (p *DefaultSegmentRegistrationPlugin) ID() string {
	return beacon.DEFAULT_GROUP
}

func (p *DefaultSegmentRegistrationPlugin) New(
	ctx context.Context,
	pc PluginConstructor,
	segType seg.Type,
	policyType beacon.PolicyType,
	config map[string]any,
) (SegmentRegistrar, error) {
	// Create either a local, hidden or remote writer.
	var writer beaconing.Writer
	switch {
	case segType != seg.TypeDown:
		writer = &beaconing.LocalWriter{
			InternalErrors: metrics.CounterWith(pc.InternalErrors, "seg_type", segType.String()),
			Registered:     pc.Registered,
			Type:           segType,
			Intfs:          pc.Intfs,
			Extender:       pc.Extender,
			Store:          pc.LocalStore,
		}
	case pc.HiddenPathRPC != nil:
		writer = &hiddenpath.BeaconWriter{
			InternalErrors: metrics.CounterWith(pc.InternalErrors, "seg_type", segType.String()),
			Registered:     pc.Registered,
			Intfs:          pc.Intfs,
			Extender:       pc.Extender,
			RPC:            pc.HiddenPathRPC,
			Pather: addrutil.Pather{
				NextHopper: pc.NextHopper,
			},
			RegistrationPolicy: pc.HiddenPathRegPolicy,
			AddressResolver:    pc.HiddenPathResolver,
		}
	default:
		writer = &beaconing.RemoteWriter{
			InternalErrors: metrics.CounterWith(pc.InternalErrors, "seg_type", segType.String()),
			Registered:     pc.Registered,
			Type:           segType,
			Intfs:          pc.Intfs,
			Extender:       pc.Extender,
			RPC:            pc.RemoteStore,
			Pather: addrutil.Pather{
				NextHopper: pc.NextHopper,
			},
		}
	}
	// Construct the registrar with the underlying writer.
	return &DefaultSegmentRegistrar{
		segType: segType,
		writer:  writer,
	}, nil
}

func (p *DefaultSegmentRegistrationPlugin) Validate(
	config map[string]any,
) error {
	// Default plugin does not have any configuration to validate.
	return nil
}

type DefaultSegmentRegistrar struct {
	segType seg.Type
	writer  beaconing.Writer
}

var _ SegmentRegistrar = (*DefaultSegmentRegistrar)(nil)

func (r *DefaultSegmentRegistrar) RegisterSegments(
	ctx context.Context,
	segments []beacon.Beacon,
	peers []uint16,
) (RegistrationStats, error) {
	writeStats, err := r.writer.Write(ctx, map[string][]beacon.Beacon{
		beacon.DEFAULT_GROUP: segments,
	}, peers)
	if err != nil {
		return RegistrationStats{}, serrors.Wrap("failed to register segments", err,
			"seg_type", r.segType, "num_segments", len(segments), "peers", peers)
	}
	// TODO: Populate the Status field.
	return RegistrationStats{
		Status:     make(map[string]error),
		WriteStats: writeStats,
	}, nil
}
