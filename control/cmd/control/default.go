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

package main

import (
	"context"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/registration"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	seg "github.com/scionproto/scion/pkg/segment"
)

// DefaultSegmentRegistrationPlugin is the default segment registration plugin.
// It uses local, remote, or hidden segment registration plugins based on the segment type.
type DefaultSegmentRegistrationPlugin struct {
	LocalPlugin  *beaconing.LocalSegmentRegistrationPlugin
	RemotePlugin *beaconing.RemoteSegmentRegistrationPlugin
	// optional
	HiddenPlugin *hiddenpath.HiddenSegmentRegistrationPlugin
}

var _ registration.SegmentRegistrationPlugin = (*DefaultSegmentRegistrationPlugin)(nil)

func (p *DefaultSegmentRegistrationPlugin) ID() string {
	return registration.DEFAULT_PLUGIN_ID
}

func (p *DefaultSegmentRegistrationPlugin) Validate(
	config map[string]any,
) error {
	// Default plugin does not have any configuration to validate.
	return nil
}

func (p *DefaultSegmentRegistrationPlugin) New(
	ctx context.Context,
	policyType beacon.RegPolicyType,
	config map[string]any,
) (registration.SegmentRegistrar, error) {
	segType := policyType.SegmentType()
	// Use either the local, hidden or remote plugin.
	var plugin registration.SegmentRegistrationPlugin
	switch {
	// For up and core segments, register locally
	case segType != seg.TypeDown:
		plugin = p.LocalPlugin
	// If segType == down && hiddenPlugin is not nil,
	// then use the hidden path registration
	case p.HiddenPlugin != nil:
		plugin = p.HiddenPlugin
	// If segType == down, then register with the remote
	default:
		plugin = p.RemotePlugin
	}
	return plugin.New(ctx, policyType, config)
}
