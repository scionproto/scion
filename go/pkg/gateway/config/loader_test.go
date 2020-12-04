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

package config_test

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/log/mock_log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/config"
	"github.com/scionproto/scion/go/pkg/gateway/config/mock_config"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/control/mock_control"
	"github.com/scionproto/scion/go/pkg/gateway/routing"
)

func TestLoaderRun(t *testing.T) {
	dir, err := ioutil.TempDir("", "gateway-config")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	writeTempFile := func(t *testing.T, raw []byte) string {
		f, err := ioutil.TempFile(dir, "gateway-config")
		require.NoError(t, err)
		_, err = f.Write(raw)
		require.NoError(t, err)
		name := f.Name()
		f.Close()
		return name
	}

	rawPol := []byte(`accept       1-ff00:0:110     1-ff00:0:112    127.0.0.0/24,127.0.1.0/24`)
	var defaultPol routing.Policy
	require.NoError(t, defaultPol.UnmarshalText(rawPol))
	rpFile := writeTempFile(t, rawPol)
	rawSP := []byte("test sessionpolicies")
	spFile := writeTempFile(t, rawSP)

	testCases := map[string]func(t *testing.T, ctrl *gomock.Controller){
		"missing publisher fails": func(t *testing.T, ctrl *gomock.Controller) {
			loader := &config.Loader{
				SessionPoliciesFile: "session.policy",
				RoutingPolicyFile:   "routing.policy",
				Trigger:             make(chan struct{}),
				SessionPolicyParser: mock_control.NewMockSessionPolicyParser(ctrl),
			}
			doneCh := make(chan struct{})
			go func() {
				defer close(doneCh)
				err := loader.Run()
				assert.Error(t, err)
			}()
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
		},
		"missing trigger fails": func(t *testing.T, ctrl *gomock.Controller) {
			loader := &config.Loader{
				SessionPoliciesFile: "session.policy",
				RoutingPolicyFile:   "routing.policy",
				Publisher:           mock_config.NewMockPublisher(ctrl),
				SessionPolicyParser: mock_control.NewMockSessionPolicyParser(ctrl),
			}
			doneCh := make(chan struct{})
			go func() {
				defer close(doneCh)
				err := loader.Run()
				assert.Error(t, err)
			}()
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
		},
		"missing session policy parser fails": func(t *testing.T, ctrl *gomock.Controller) {
			loader := &config.Loader{
				SessionPoliciesFile: "session.policy",
				RoutingPolicyFile:   "routing.policy",
				Publisher:           mock_config.NewMockPublisher(ctrl),
				Trigger:             make(chan struct{}),
			}
			doneCh := make(chan struct{})
			go func() {
				defer close(doneCh)
				err := loader.Run()
				assert.Error(t, err)
			}()
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
		},
		"missing session policy file fails": func(t *testing.T, ctrl *gomock.Controller) {
			loader := &config.Loader{
				RoutingPolicyFile:   "routing.policy",
				Publisher:           mock_config.NewMockPublisher(ctrl),
				Trigger:             make(chan struct{}),
				SessionPolicyParser: mock_control.NewMockSessionPolicyParser(ctrl),
			}
			doneCh := make(chan struct{})
			go func() {
				defer close(doneCh)
				err := loader.Run()
				assert.Error(t, err)
			}()
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
		},
		"close before run immediately returns": func(t *testing.T, ctrl *gomock.Controller) {
			loader := &config.Loader{
				SessionPoliciesFile: "session.policy",
				RoutingPolicyFile:   "routing.policy",
				Publisher:           mock_config.NewMockPublisher(ctrl),
				Trigger:             make(chan struct{}),
				SessionPolicyParser: mock_control.NewMockSessionPolicyParser(ctrl),
			}
			doneCh := make(chan struct{})
			assert.NoError(t, loader.Close())
			go func() {
				defer close(doneCh)
				err := loader.Run()
				assert.NoError(t, err)
			}()
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
		},
		"load existing files": func(t *testing.T, ctrl *gomock.Controller) {
			stopCh := make(chan struct{})

			publisher := mock_config.NewMockPublisher(ctrl)
			sessPols := control.SessionPolicies{{IA: xtest.MustParseIA("1-ff00:0:110")}}
			publisher.EXPECT().Publish(sessPols, &defaultPol).Do(
				func(control.SessionPolicies, *routing.Policy) { close(stopCh) })
			parser := mock_control.NewMockSessionPolicyParser(ctrl)
			parser.EXPECT().Parse(rawSP).Return(sessPols, nil)
			trigger := make(chan struct{})
			logger := mock_log.NewMockLogger(ctrl)
			logger.EXPECT().Info(gomock.Any(), gomock.Any())
			loader := &config.Loader{
				SessionPoliciesFile: spFile,
				RoutingPolicyFile:   rpFile,
				Publisher:           publisher,
				Trigger:             trigger,
				SessionPolicyParser: parser,
				Logger:              logger,
			}
			doneCh := make(chan struct{})
			go func() {
				defer close(doneCh)
				err := loader.Run()
				assert.NoError(t, err)
			}()
			select {
			case trigger <- struct{}{}:
			case <-time.After(time.Second):
				t.Fatalf("Time out")
			}
			xtest.AssertReadReturnsBefore(t, stopCh, time.Second)
			assert.NoError(t, loader.Close())
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
		},
		"session policy load error": func(t *testing.T, ctrl *gomock.Controller) {
			stopCh := make(chan struct{})
			publisher := mock_config.NewMockPublisher(ctrl)
			publisher.EXPECT().Publish(nil, &defaultPol).Do(
				func(control.SessionPolicies, *routing.Policy) { close(stopCh) })
			parser := mock_control.NewMockSessionPolicyParser(ctrl)
			parser.EXPECT().Parse(rawSP).Return(nil, serrors.New("test err"))
			logger := mock_log.NewMockLogger(ctrl)
			logger.EXPECT().Error(gomock.Any(), gomock.Any())
			logger.EXPECT().Info(gomock.Any(), gomock.Any())
			trigger := make(chan struct{})
			loader := &config.Loader{
				SessionPoliciesFile: spFile,
				RoutingPolicyFile:   rpFile,
				Publisher:           publisher,
				Trigger:             trigger,
				SessionPolicyParser: parser,
				Logger:              logger,
			}
			doneCh := make(chan struct{})
			go func() {
				defer close(doneCh)
				err := loader.Run()
				assert.NoError(t, err)
			}()
			select {
			case trigger <- struct{}{}:
			case <-time.After(time.Second):
				t.Fatalf("Time out")
			}
			xtest.AssertReadReturnsBefore(t, stopCh, time.Second)
			assert.NoError(t, loader.Close())
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
		},
		"load default routing policy": func(t *testing.T, ctrl *gomock.Controller) {
			stopCh := make(chan struct{})
			publisher := mock_config.NewMockPublisher(ctrl)
			sessPols := control.SessionPolicies{{IA: xtest.MustParseIA("1-ff00:0:110")}}
			defaultRP := &routing.Policy{DefaultAction: routing.Reject}
			publisher.EXPECT().Publish(sessPols, defaultRP).Do(
				func(control.SessionPolicies, *routing.Policy) { close(stopCh) })
			parser := mock_control.NewMockSessionPolicyParser(ctrl)
			parser.EXPECT().Parse(rawSP).Return(sessPols, nil)
			trigger := make(chan struct{})
			logger := mock_log.NewMockLogger(ctrl)
			logger.EXPECT().Info(gomock.Any(), gomock.Any())
			loader := &config.Loader{
				SessionPoliciesFile: spFile,
				RoutingPolicyFile:   "",
				Publisher:           publisher,
				Trigger:             trigger,
				SessionPolicyParser: parser,
				Logger:              logger,
			}
			doneCh := make(chan struct{})
			go func() {
				defer close(doneCh)
				err := loader.Run()
				assert.NoError(t, err)
			}()
			select {
			case trigger <- struct{}{}:
			case <-time.After(time.Second):
				t.Fatalf("Time out")
			}
			xtest.AssertReadReturnsBefore(t, stopCh, time.Second)
			assert.NoError(t, loader.Close())
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			tc(t, ctrl)
		})
	}
}
