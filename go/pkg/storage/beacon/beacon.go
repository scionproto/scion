// Copyright 2021 Anapaya Systems
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

package beacon

import (
	"context"
	"time"
)

// Cleanable is a database that needs periodic clean up of expired beacons.
type Cleanable interface {
	// DeleteExpiredBeacons removes all beacons that have an expiration time
	// before the passed time value.
	// The return value indicates the number of beacons that were removed.
	DeleteExpiredBeacons(ctx context.Context, now time.Time) (int, error)
}
