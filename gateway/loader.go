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

package gateway

import (
	"context"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/routing"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/worker"
)

// Publisher publishes new configurations.
type Publisher interface {
	Publish(control.SessionPolicies, *routing.Policy)
}

// Loader can be used to load gateway configurations from files. It waits on
// triggers.
type Loader struct {
	// SessionPoliciesFile is the file name of the session policies. Must be set.
	SessionPoliciesFile string
	// RoutingPolicyFile is the file name of the routing policy. Must be set.
	RoutingPolicyFile string
	// Publisher is used to publish new loaded configs.
	Publisher Publisher
	// Trigger is used to trigger loading.
	Trigger <-chan struct{}
	// SessionPolicyParser is used to parse session policies.
	SessionPolicyParser control.SessionPolicyParser

	workerBase worker.Base
}

// Run waits on trigger signals, and publishes the newly loaded files on the
// trigger. This blocks until the Loader is closed.
func (l *Loader) Run(ctx context.Context) error {
	return l.workerBase.RunWrapper(ctx, l.validate, l.run)
}

// Close shuts down this loader.
func (l *Loader) Close(ctx context.Context) error {
	return l.workerBase.CloseWrapper(ctx, nil)
}

func (l *Loader) validate(ctx context.Context) error {
	if l.SessionPoliciesFile == "" {
		return serrors.New("SessionPoliciesFile must be set")
	}
	if l.Publisher == nil {
		return serrors.New("Publisher must be set")
	}
	if l.Trigger == nil {
		return serrors.New("Trigger channel must be set")
	}
	if l.SessionPolicyParser == nil {
		return serrors.New("SessionPolicyParse must be set")
	}
	return nil
}

func (l *Loader) run(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	for {
		select {
		case <-l.Trigger:
			sp, rp, err := l.loadFiles(ctx)
			if err != nil {
				logger.Error("Failed to load files", "err", err)
			}
			if sp == nil && rp == nil {
				continue
			}
			l.Publisher.Publish(sp, rp)
			logger.Info("Published new configurations",
				"session_policies", sp != nil, "routing_policy", rp != nil)
		case <-l.workerBase.GetDoneChan():
			return nil
		}
	}
}

func (l *Loader) loadFiles(ctx context.Context) (control.SessionPolicies, *routing.Policy, error) {
	var errors serrors.List
	sp, err := control.LoadSessionPolicies(ctx, l.SessionPoliciesFile, l.SessionPolicyParser)
	if err != nil {
		errors = append(errors, serrors.Wrap("loading session policies", err))
	}
	rp, err := l.loadRoutingPolicy()
	if err != nil {
		errors = append(errors, serrors.Wrap("loading routing policiy", err))
	}
	return sp, rp, errors.ToError()
}

func (l *Loader) loadRoutingPolicy() (*routing.Policy, error) {
	if l.RoutingPolicyFile == "" {
		// return a default routing policy that rejects everything.
		return &routing.Policy{DefaultAction: routing.Reject}, nil
	}
	rp, err := routing.LoadPolicy(l.RoutingPolicyFile)
	if err != nil {
		return nil, err
	}
	return &rp, nil
}
