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

package standalone

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/asinfo"
	"github.com/scionproto/scion/pkg/daemon/private/engine"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/storage"
)

// Daemon implements the daemon.Connector interface by directly
// delegating to a DaemonEngine. This allows in-process usage of daemon
// functionality without going through gRPC.
// Also collects metrics for all operations.
//
// Close() will clean up all resources, including LocalASInfo if it implements
// io.Closer.
type Daemon struct {
	Engine        *engine.DaemonEngine
	Metrics       Metrics
	LocalASInfo   asinfo.LocalASInfo
	PathDBCleaner *periodic.Runner
	PathDB        storage.PathDB
	RevCache      revcache.RevCache
	RcCleaner     *periodic.Runner
	TrustDB       storage.TrustDB
	TRCLoaderTask *periodic.Runner
}

// LocalIA returns the local ISD-AS number.
func (s *Daemon) LocalIA(ctx context.Context) (addr.IA, error) {
	start := time.Now()
	ia, err := s.Engine.LocalIA(ctx)
	s.Metrics.LocalIA.Observe(err, time.Since(start))
	return ia, err
}

// PortRange returns the beginning and the end of the SCION/UDP endhost port range.
func (s *Daemon) PortRange(ctx context.Context) (uint16, uint16, error) {
	start := time.Now()
	startPort, endPort, err := s.Engine.PortRange(ctx)
	s.Metrics.PortRange.Observe(err, time.Since(start))
	return startPort, endPort, err
}

// Interfaces returns the map of interface identifiers to the underlay internal address.
func (s *Daemon) Interfaces(ctx context.Context) (map[uint16]netip.AddrPort, error) {
	start := time.Now()
	result, err := s.Engine.Interfaces(ctx)
	s.Metrics.Interfaces.Observe(err, time.Since(start))
	return result, err
}

// Paths requests from the daemon a set of end to end paths between the source and destination.
func (s *Daemon) Paths(
	ctx context.Context,
	dst, src addr.IA,
	f types.PathReqFlags,
) ([]snet.Path, error) {
	start := time.Now()
	paths, err := s.Engine.Paths(ctx, dst, src, f)
	s.Metrics.Paths.Observe(err, time.Since(start), prom.LabelDst, dst.ISD().String())
	return paths, err
}

// ASInfo requests information about an AS. The zero IA returns local AS info.
func (s *Daemon) ASInfo(ctx context.Context, ia addr.IA) (types.ASInfo, error) {
	start := time.Now()
	asInfo, err := s.Engine.ASInfo(ctx, ia)
	s.Metrics.ASInfo.Observe(err, time.Since(start))
	return asInfo, err
}

// SVCInfo requests information about addresses and ports of infrastructure services.
func (s *Daemon) SVCInfo(
	ctx context.Context,
	_ []addr.SVC,
) (map[addr.SVC][]string, error) {
	start := time.Now()
	uris, err := s.Engine.SVCInfo(ctx)
	s.Metrics.SVCInfo.Observe(err, time.Since(start))
	if err != nil {
		return nil, err
	}
	result := make(map[addr.SVC][]string)
	if len(uris) > 0 {
		result[addr.SvcCS] = uris
	}
	return result, nil
}

// RevNotification sends a RevocationInfo message to the daemon.
func (s *Daemon) RevNotification(
	ctx context.Context,
	revInfo *path_mgmt.RevInfo,
) error {
	start := time.Now()
	err := s.Engine.NotifyInterfaceDown(ctx, revInfo.RawIsdas, uint64(revInfo.IfID))
	s.Metrics.InterfaceDown.Observe(err, time.Since(start))
	return err
}

// DRKeyGetASHostKey requests an AS-Host Key from the daemon.
func (s *Daemon) DRKeyGetASHostKey(
	ctx context.Context,
	meta drkey.ASHostMeta,
) (drkey.ASHostKey, error) {
	start := time.Now()
	key, err := s.Engine.DRKeyGetASHostKey(ctx, meta)
	s.Metrics.DRKeyASHost.Observe(err, time.Since(start))
	return key, err
}

// DRKeyGetHostASKey requests a Host-AS Key from the daemon.
func (s *Daemon) DRKeyGetHostASKey(
	ctx context.Context,
	meta drkey.HostASMeta,
) (drkey.HostASKey, error) {
	start := time.Now()
	key, err := s.Engine.DRKeyGetHostASKey(ctx, meta)
	s.Metrics.DRKeyHostAS.Observe(err, time.Since(start))
	return key, err
}

// DRKeyGetHostHostKey requests a Host-Host Key from the daemon.
func (s *Daemon) DRKeyGetHostHostKey(
	ctx context.Context,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {
	start := time.Now()
	key, err := s.Engine.DRKeyGetHostHostKey(ctx, meta)
	s.Metrics.DRKeyHostHost.Observe(err, time.Since(start))
	return key, err
}

func (s *Daemon) Close() error {
	var err error
	if s.PathDBCleaner != nil {
		s.PathDBCleaner.Stop()
	}
	if s.PathDB != nil {
		err1 := s.PathDB.Close()
		err = errors.Join(err, err1)
	}
	if s.RevCache != nil {
		err1 := s.RevCache.Close()
		err = errors.Join(err, err1)
	}
	if s.RcCleaner != nil {
		s.RcCleaner.Stop()
	}
	if s.TrustDB != nil {
		err1 := s.TrustDB.Close()
		err = errors.Join(err, err1)
	}
	if s.TRCLoaderTask != nil {
		s.TRCLoaderTask.Stop()
	}
	// Close LocalASInfo if it implements io.Closer.
	if closer, ok := s.LocalASInfo.(io.Closer); ok {
		err1 := closer.Close()
		err = errors.Join(err, err1)
	}
	return err
}
