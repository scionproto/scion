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

package segreg

import (
	"context"
	"fmt"

	"github.com/scionproto/scion/control/beacon"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// DefaultPluginID is the id for the default segment registration plugin.
// It is used for the policies that do not have any registration policies.
const DefaultPluginID string = "default"

type SegmentRegistrationPlugin interface {
	// ID returns the unique identifier of the plugin.
	ID() string
	// New creates a new instance of the plugin with the provided configuration.
	New(
		ctx context.Context,
		policyType beacon.RegPolicyType,
		config map[string]any,
	) (SegmentRegistrar, error)
	// Validate validates the configuration of the plugin.
	Validate(config map[string]any) error
}

type SegmentRegistrar interface {
	// RegisterSegments registers the given segments with the given type according
	// to the plugin's logic. It should either log or handle the errors.
	RegisterSegments(
		ctx context.Context,
		segments []beacon.Beacon,
		peers []uint16,
	) *RegistrationSummary
}

// SegmentRegistrars maps a policy type to a map of registration policy names
// to their corresponding segment registrars.
type SegmentRegistrars map[beacon.RegPolicyType]map[string]SegmentRegistrar

// RegisterSegmentRegistrar registers a segment registrar for a given policy type and
// registration policy.
func (s SegmentRegistrars) RegisterSegmentRegistrar(
	policyType beacon.RegPolicyType,
	registrationPolicy string,
	registrar SegmentRegistrar,
) error {
	if _, ok := s[policyType]; !ok {
		s[policyType] = make(map[string]SegmentRegistrar)
	}
	if _, ok := s[policyType][registrationPolicy]; ok {
		return serrors.New("registrar already registered for policy type and registration policy",
			"policy_type", policyType, "registration_policy", registrationPolicy)
	}
	s[policyType][registrationPolicy] = registrar
	return nil
}

// RegisterDefaultSegmentRegistrar registers a default registrar for a given policy type.
// The default registrar should be registered when no specific registration policy is defined
// for policyType. The default registrar is associated with the name beacon.DefaultGroup.
func (s SegmentRegistrars) RegisterDefaultSegmentRegistrar(
	policyType beacon.RegPolicyType, registrar SegmentRegistrar,
) error {
	if _, ok := s[policyType]; !ok {
		s[policyType] = make(map[string]SegmentRegistrar)
	}
	if _, ok := s[policyType][beacon.DefaultGroup]; ok {
		return serrors.New("default registrar already registered for policy type",
			"policy_type", policyType)
	}
	s[policyType][beacon.DefaultGroup] = registrar
	return nil
}

// GetSegmentRegistrar returns the segment registrar for the given policy type and registration
// policy.
// It should be registered with either RegisterSegmentRegistrar or RegisterDefaultRegistrar
// first.
func (s SegmentRegistrars) GetSegmentRegistrar(
	policyType beacon.RegPolicyType, registrationPolicy string,
) (SegmentRegistrar, error) {
	if _, ok := s[policyType]; !ok {
		return nil, serrors.New("no registrars found for policy type",
			"policy_type", policyType)
	}
	registrar, ok := s[policyType][registrationPolicy]
	if !ok {
		return nil, serrors.New("no registrar found for registration policy",
			"registration_policy", registrationPolicy, "policy_type", policyType)
	}
	return registrar, nil
}

// segmentRegistrationPlugins is a global map of registered segment registration plugins.
var segmentRegistrationPlugins = map[string]SegmentRegistrationPlugin{}

// RegisterSegmentRegPlugin registers a segment registration plugin using its unique ID.
// It panics if a plugin with the same ID is already registered.
func RegisterSegmentRegPlugin(p SegmentRegistrationPlugin) {
	id := p.ID()
	if _, ok := segmentRegistrationPlugins[id]; ok {
		panic(fmt.Sprintf("plugin %q already registered", id))
	}
	segmentRegistrationPlugins[id] = p
}

// GetSegmentRegPlugin retrieves a segment registration plugin by its ID.
// It should be registered with RegisterSegmentRegPlugin first.
// The second return value is false if no plugin with the given ID is found in the registry.
func GetSegmentRegPlugin(id string) (SegmentRegistrationPlugin, bool) {
	p, ok := segmentRegistrationPlugins[id]
	return p, ok
}

// GetDefaultSegmentRegPlugin retrieves the segment registration plugin that has the
// id DefaultPluginID.
func GetDefaultSegmentRegPlugin() (SegmentRegistrationPlugin, bool) {
	plugin, ok := GetSegmentRegPlugin(DefaultPluginID)
	if !ok {
		return nil, false
	}
	return plugin, true
}
