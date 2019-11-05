// Copyright 2018 Anapaya Systems
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

package healthpool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testInfo struct {
	Info
	name string
}

func TestNewPool(t *testing.T) {
	_, _, infos := testInfoSet()
	tests := map[string]struct {
		Infos     InfoSet
		Options   PoolOptions
		Assertion require.ErrorAssertionFunc
	}{
		"valid": {
			Infos:     infos,
			Assertion: require.NoError,
		},
		"allow empty": {
			Options:   PoolOptions{AllowEmpty: true},
			Assertion: require.NoError,
		},
		"empty": {
			Assertion: require.Error,
		},
		"invalid algorithm": {
			Options:   PoolOptions{Algorithm: "invalid", AllowEmpty: true},
			Assertion: require.Error,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, err := NewPool(test.Infos, test.Options)
			test.Assertion(t, err)
			if err == nil {
				assert.ElementsMatch(t, test.Infos.List(), p.Infos())
			}
		})
	}
}

func TestPoolUpdate(t *testing.T) {
	_, two, infos := testInfoSet()
	p, err := NewPool(infos, PoolOptions{})
	require.NoError(t, err)

	// Added entry should be part of the pool.
	infos[newTestInfo("three")] = struct{}{}
	err = p.Update(infos)
	require.NoError(t, err)
	assert.ElementsMatch(t, infos.List(), p.Infos())

	// Removed entry should no longer be part of the pool.
	delete(infos, two)
	err = p.Update(infos)
	require.NoError(t, err)
	assert.ElementsMatch(t, infos.List(), p.Infos())
	assert.NotContains(t, p.Infos(), two)

	// Empty update only succeeds when allow empty is set.
	err = p.Update(nil)
	require.Error(t, err)
	p.opts.AllowEmpty = true
	err = p.Update(nil)
	require.NoError(t, err)
}

func TestPoolChoose(t *testing.T) {
	one, two, infos := testInfoSet()
	p, err := NewPool(infos, PoolOptions{})
	require.NoError(t, err)

	one.Fail()
	i, err := p.Choose()
	require.NoError(t, err)
	assert.Equal(t, two, i)

	two.Fail()
	two.Fail()
	i, err = p.Choose()
	require.NoError(t, err)
	assert.Equal(t, one, i)

	two.ResetCount()
	i, err = p.Choose()
	require.NoError(t, err)
	assert.Equal(t, two, i)

	one.(*testInfo).Info.(*info).fails = uint16(MaxFailCount)
	two.(*testInfo).Info.(*info).fails = uint16(MaxFailCount)
	_, err = p.Choose()
	assert.NoError(t, err)
}

func TestPoolChooseEmpty(t *testing.T) {
	p, err := NewPool(nil, PoolOptions{AllowEmpty: true})
	require.NoError(t, err)
	_, err = p.Choose()
	assert.Error(t, err)
}

func TestPoolClose(t *testing.T) {
	_, _, infos := testInfoSet()
	p, err := NewPool(infos, PoolOptions{})
	require.NoError(t, err)
	p.Close()
	_, err = p.Choose()
	assert.Error(t, err)
	assert.Error(t, p.Update(infos))
	assert.NotPanics(t, p.Close)
}

func TestPoolExpiresFails(t *testing.T) {
	initTime := time.Now().Add(-(time.Hour + 10*time.Second))
	one := &info{
		lastExp:  initTime,
		lastFail: initTime,
		fails:    64,
	}
	two := &info{
		lastExp:  initTime,
		lastFail: initTime,
		fails:    128,
	}
	infos := InfoSet{
		one: {},
		two: {},
	}
	p, err := NewPool(
		infos,
		PoolOptions{
			Expire: ExpireOptions{
				Interval: time.Hour / 2,
				Start:    time.Nanosecond,
			},
		},
	)
	require.NoError(t, err)
	p.expirer.TriggerRun()
	time.Sleep(time.Second)
	assert.Equal(t, 16, one.FailCount())
	assert.Equal(t, 32, two.FailCount())
}

func testInfoSet() (Info, Info, InfoSet) {
	one := newTestInfo("one")
	two := newTestInfo("two")
	infos := InfoSet{
		one: {},
		two: {},
	}
	return one, two, infos
}

func newTestInfo(name string) *testInfo {
	return &testInfo{
		Info: NewInfo(),
		name: name,
	}
}
