package drkeyutil

import (
	"os"
	"time"

	"github.com/scionproto/scion/pkg/private/util"
)

const (
	// DefaultEpochDuration is the default duration for the drkey SecretValue and derived keys
	DefaultEpochDuration   = 24 * time.Hour
	DefaultPrefetchEntries = 10000
	EnvVarEpochDuration    = "SCION_TESTING_DRKEY_EPOCH_DURATION"
	// DefaultAcceptanceWindowOffset is the time width for accepting incoming packets. The
	// acceptance widown is then compute as:
	// aw := [T-a, T+a)
	// where aw:= acceptance window, T := time instant and a := acceptanceWindowOffset
	//
	// Picking the value equal or shorter than half of the drkey Grace Period ensures
	// that we accept packets for active keys only.
	DefaultAcceptanceWindowLength = 5
	EnvVarAccpetanceWindow        = "SCION_TESTING_ACCEPTANCE_WINDOW"
)

func LoadEpochDuration() time.Duration {
	s := os.Getenv(EnvVarEpochDuration)
	if s == "" {
		return DefaultEpochDuration
	}
	duration, err := util.ParseDuration(s)
	if err != nil {
		return DefaultEpochDuration
	}
	return duration
}

func LoadAcceptanceWindow() time.Duration {
	s := os.Getenv(EnvVarAccpetanceWindow)
	if s == "" {
		return DefaultAcceptanceWindowLength
	}
	duration, err := util.ParseDuration(s)
	if err != nil {
		return DefaultAcceptanceWindowLength
	}
	return duration
}
