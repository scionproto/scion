// Copyright 2022 ETH Zurich
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

package drkeytest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/drkey/generic"
	"github.com/scionproto/scion/pkg/drkey/specific"
)

func GetLevel1(t *testing.T, protoID drkey.Protocol, epoch drkey.Epoch,
	srcIA, dstIA addr.IA) drkey.Level1Key {
	asSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	asSecret = append(asSecret, byte(srcIA))
	sv, err := drkey.DeriveSV(protoID, epoch, asSecret)
	require.NoError(t, err)

	key, err := (&specific.Deriver{}).DeriveLevel1(dstIA, sv.Key)
	require.NoError(t, err)
	return drkey.Level1Key{
		Epoch:   sv.Epoch,
		SrcIA:   srcIA,
		DstIA:   dstIA,
		ProtoId: sv.ProtoId,
		Key:     key,
	}
}

func DeriveASHostGeneric(meta drkey.ASHostMeta,
	level1key drkey.Level1Key) (drkey.ASHostKey, error) {

	derivedKey, err := (&generic.Deriver{}).DeriveASHost(meta.ProtoId, meta.DstHost,
		level1key.Key)
	if err != nil {
		return drkey.ASHostKey{}, err
	}

	return drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   level1key.Epoch,
		SrcIA:   level1key.SrcIA,
		DstIA:   level1key.DstIA,
		DstHost: meta.DstHost,
		Key:     derivedKey,
	}, nil
}

func DeriveHostASGeneric(meta drkey.HostASMeta,
	level1key drkey.Level1Key) (drkey.HostASKey, error) {
	derivedKey, err := (&generic.Deriver{}).DeriveHostAS(meta.ProtoId, meta.SrcHost,
		level1key.Key)
	if err != nil {
		return drkey.HostASKey{}, err
	}

	return drkey.HostASKey{
		ProtoId: meta.ProtoId,
		Epoch:   level1key.Epoch,
		SrcIA:   level1key.SrcIA,
		DstIA:   level1key.DstIA,
		SrcHost: meta.SrcHost,
		Key:     derivedKey,
	}, nil
}

func DeriveHostHostGeneric(meta drkey.HostHostMeta,
	level1key drkey.Level1Key) (drkey.HostHostKey, error) {

	hostASKey, err := (&generic.Deriver{}).DeriveHostAS(meta.ProtoId, meta.SrcHost,
		level1key.Key)
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	h2hKey, err := (&generic.Deriver{}).DeriveHostToHost(meta.DstHost, hostASKey)
	if err != nil {
		return drkey.HostHostKey{}, err
	}

	return drkey.HostHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   level1key.Epoch,
		SrcIA:   level1key.SrcIA,
		DstIA:   level1key.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
		Key:     h2hKey,
	}, nil
}

func DeriveASHostSpecific(meta drkey.ASHostMeta,
	level1key drkey.Level1Key) (drkey.ASHostKey, error) {

	derivedKey, err := (&specific.Deriver{}).DeriveASHost(meta.DstHost, level1key.Key)
	if err != nil {
		return drkey.ASHostKey{}, err
	}

	return drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   level1key.Epoch,
		SrcIA:   level1key.SrcIA,
		DstIA:   level1key.DstIA,
		DstHost: meta.DstHost,
		Key:     derivedKey,
	}, nil
}

func DeriveHostASSpecific(meta drkey.HostASMeta,
	level1key drkey.Level1Key) (drkey.HostASKey, error) {

	derivedKey, err := (&specific.Deriver{}).DeriveHostAS(meta.SrcHost, level1key.Key)
	if err != nil {
		return drkey.HostASKey{}, err
	}

	return drkey.HostASKey{
		ProtoId: meta.ProtoId,
		Epoch:   level1key.Epoch,
		SrcIA:   level1key.SrcIA,
		DstIA:   level1key.DstIA,
		SrcHost: meta.SrcHost,
		Key:     derivedKey,
	}, nil
}

func DeriveHostHostSpecific(meta drkey.HostHostMeta,
	level1key drkey.Level1Key) (drkey.HostHostKey, error) {

	hostASKey, err := (&specific.Deriver{}).DeriveHostAS(meta.SrcHost, level1key.Key)
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	h2hKey, err := (&specific.Deriver{}).DeriveHostToHost(meta.DstHost, hostASKey)
	if err != nil {
		return drkey.HostHostKey{}, err
	}

	return drkey.HostHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   level1key.Epoch,
		SrcIA:   level1key.SrcIA,
		DstIA:   level1key.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
		Key:     h2hKey,
	}, nil
}
