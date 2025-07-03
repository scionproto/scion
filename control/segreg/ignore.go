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
	"strings"
	"text/template"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
)

const (
	ConfigKeyLogLevel string = "Level"
	ConfigKeyMessage  string = "Message"
)

// logLevel defines the logging level for the IgnoreSegmentRegistrationPlugin.
type logLevel string

const (
	LogLevelDebug logLevel = "debug"
	LogLevelInfo  logLevel = "info"
	LogLevelError logLevel = "error"
)

func parseLogLevel(s string) (logLevel, error) {
	switch s {
	case string(LogLevelDebug), string(LogLevelInfo), string(LogLevelError):
		return logLevel(s), nil
	default:
		return "", serrors.New("invalid log level", "level", s)
	}
}

type pluginConfig struct {
	Level   logLevel
	Message *template.Template
}

func parseConfig(config map[string]any) (pluginConfig, error) {
	// Extract the log level and message from the config.
	level := LogLevelDebug // Default log level
	var message *template.Template
	if val, ok := config[ConfigKeyLogLevel]; ok {
		strVal, ok := val.(string)
		if !ok {
			return pluginConfig{}, serrors.New("invalid log level value",
				"key", ConfigKeyLogLevel)
		}
		logLevel, err := parseLogLevel(strVal)
		if err != nil {
			return pluginConfig{}, serrors.Wrap("parsing log level", err,
				"key", ConfigKeyLogLevel,
				"value", strVal)
		}
		level = logLevel
	}
	if val, ok := config[ConfigKeyMessage]; ok {
		strVal, ok := val.(string)
		if !ok {
			return pluginConfig{}, serrors.New("invalid message value",
				"key", ConfigKeyMessage)
		}
		tmpl, err := template.New("message").Parse(strVal)
		if err != nil {
			return pluginConfig{}, serrors.Wrap("parsing message template", err,
				"key", ConfigKeyMessage,
				"value", strVal)
		}
		message = tmpl
	}
	return pluginConfig{Level: level, Message: message}, nil
}

type IgnoreSegmentRegistrationPlugin struct{}

var _ SegmentRegistrationPlugin = (*IgnoreSegmentRegistrationPlugin)(nil)

func (p *IgnoreSegmentRegistrationPlugin) ID() string {
	return "ignore"
}

func (p *IgnoreSegmentRegistrationPlugin) Validate(
	config map[string]any,
) error {
	_, err := parseConfig(config)
	if err != nil {
		return serrors.Wrap("validating plugin configuration", err)
	}
	return nil
}

func (p *IgnoreSegmentRegistrationPlugin) New(
	ctx context.Context,
	policyType beacon.RegPolicyType,
	config map[string]any,
) (SegmentRegistrar, error) {
	conf, err := parseConfig(config)
	if err != nil {
		return nil, serrors.Wrap("parsing plugin configuration", err)
	}
	return &IgnoreSegmentRegistrar{pluginConfig: conf}, nil
}

type IgnoreSegmentRegistrar struct {
	pluginConfig
}

var _ SegmentRegistrar = (*IgnoreSegmentRegistrar)(nil)

type tmplData struct {
	Segment beacon.Beacon
}

func (r *IgnoreSegmentRegistrar) RegisterSegments(
	ctx context.Context,
	segments []beacon.Beacon,
	peers []uint16,
) *RegistrationSummary {
	// Create the logger.
	logger := log.FromCtx(ctx)

	// Build up a registration status that reports success for all segments.
	startIAs := make(map[addr.IA]struct{})
	for _, b := range segments {
		startIA := b.Segment.FirstIA()
		startIAs[startIA] = struct{}{}
	}

	// If no message is configured, we do not log anything.
	if r.Message == nil {
		return nil
	}

	summary := NewSummary()

	for _, b := range segments {
		var sb strings.Builder

		// Execute the message template and get the formatted message.
		if err := r.Message.Execute(&sb, tmplData{
			Segment: b,
		}); err != nil {
			logger.Error("Failed to execute message template",
				"err", err,
			)
			continue
		}
		s := sb.String()

		// Log the message at the configured log level.
		switch r.Level {
		case LogLevelDebug:
			logger.Debug(s)
		case LogLevelInfo:
			logger.Info(s)
		case LogLevelError:
			logger.Error(s)
		default:
			panic("unexpected log level") // This should never happen due to validation.
		}

		summary.RecordBeacon(&b)
	}
	return summary
}
