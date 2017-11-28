# Copyright 2017 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`path_combinator` --- Methods to build SCION end-to-end paths.
===================================================================
"""
# Stdlib
import logging

# SCION
from lib.crypto.hash_tree import ConnectedHashTree
from lib.defines import SCION_MIN_MTU
from lib.packet.path import SCIONPath
from lib.sciond_api.path_meta import FwdPathMeta, PathInterface


def build_shortcut_paths(up_segments, down_segments, peer_revs):
    """
    Returns a list of all shortcut paths (peering and crossover paths) that
    can be built using the provided up- and down-segments.

    :param list up_segments: List of `up` PathSegments.
    :param list down_segments: List of `down` PathSegments.
    :param RevCache peer_revs: Peering revocations.
    :returns: List of FwdPathMeta objects.
    """
    path_metas = []
    for up in up_segments:
        for down in down_segments:
            for path_meta in _build_shortcuts(up, down, peer_revs):
                if path_meta and path_meta not in path_metas:
                    path_metas.append(path_meta)
    return path_metas


def _build_shortcuts(up_segment, down_segment, peer_revs):
    """
    Takes :any:`PathSegment`\s and tries to combine them into short path via
    any cross-over or peer links found.

    :param list up_segment: `up` :any:`PathSegment`.
    :param list down_segment: `down` :any:`PathSegment`.
    :param RevCache peer_revs: Peering revocations.
    :returns: SCIONPath if a shortcut path is found, otherwise ``None``.
    """
    # TODO check if stub ASs are the same...
    if (not up_segment or not down_segment or
            not up_segment.p.asEntries or not down_segment.p.asEntries):
        return []

    # looking for xovr and peer points
    xovr, peer = _get_xovr_peer(up_segment, down_segment, peer_revs)

    if not xovr and not peer:
        return []

    def _sum_pt(pt):
        if pt is None:
            return 0
        return sum(pt)

    if _sum_pt(peer) > _sum_pt(xovr):
        # Peer is best.
        return _join_peer(up_segment, down_segment, peer, peer_revs)
    else:
        # Xovr is best
        return _join_xovr(up_segment, down_segment, xovr)


def _copy_segment(segment, xover_start, xover_end, up=True):
    """
    Copy a :any:`PathSegment`, setting the up flag, the crossover point
    flags, and optionally reversing the hops.
    """
    if not segment:
        return None, None, float("inf")
    info = segment.infoF()
    info.up_flag = up
    hofs, mtu = _copy_hofs(segment.iter_asms(), reverse=up)
    if xover_start:
        hofs[0].xover = True
    if xover_end:
        hofs[-1].xover = True
    return info, hofs, mtu


def _get_xovr_peer(up_segment, down_segment, peer_revs):
    """
    Find the shortest xovr (preferred) and peer points between the supplied
    segments.

    *Note*: 'shortest' is calculated by looking for the point that's
    furthest from the core.

    :param list up_segment: `up` :any:`PathSegment`.
    :param list down_segment: `down` :any:`PathSegment`.
    :param RevCache peer_revs: Peering revocations.
    :returns:
        Tuple of the shortest xovr and peer points.
    """
    xovrs = []
    peers = []
    for up_i, up_asm in enumerate(up_segment.iter_asms(1), 1):
        for down_i, down_asm in enumerate(down_segment.iter_asms(1), 1):
            up_ia = up_asm.isd_as()
            down_ia = down_asm.isd_as()
            if up_ia == down_ia:
                xovrs.append((up_i, down_i))
                continue
            if _find_peer_hfs(up_asm, down_asm, peer_revs):
                peers.append((up_i, down_i))
    xovr = peer = None
    if xovrs:
        xovr = max(xovrs, key=lambda tup: sum(tup))
    if peers:
        peer = max(peers, key=lambda tup: sum(tup))
    return xovr, peer


def _join_xovr(up_segment, down_segment, point):
    """
    Joins the supplied segments into a shortcut (xovr) fullpath.

    :param list up_segment: `up` :any:`PathSegment`.
    :param list down_segment: `down` :any:`PathSegment`.
    :param tuple point: Indexes of xovr point.
    :returns: :any:`CrossOverPath`.
    """
    (up_index, down_index) = point

    up_iof, up_hofs, up_upstream_hof, up_mtu = \
        _copy_segment_shortcut(up_segment, up_index)
    down_iof, down_hofs, down_upstream_hof, down_mtu = \
        _copy_segment_shortcut(down_segment, down_index, up=False)

    up_iof.shortcut = down_iof.shortcut = True
    up_iof.peer = down_iof.peer = False
    up_hofs.append(up_upstream_hof)
    down_hofs.insert(0, down_upstream_hof)
    args = _shortcut_path_args(up_iof, up_hofs, down_iof, down_hofs)
    path = SCIONPath.from_values(*args)
    if_list = _build_shortcut_interface_list(
        up_segment, up_index, down_segment, down_index)
    mtu = _min_mtu(up_mtu, down_mtu)
    path_meta = FwdPathMeta.from_values(path, if_list, mtu)
    return [path_meta]


def _join_peer(up_segment, down_segment, point, peer_revs):
    """
    Joins the supplied segments into a shortcut (peer) fullpath.

    :param list up_segment: `up` :any:`PathSegment`.
    :param list down_segment: `down` :any:`PathSegment`.
    :param tuple point: Indexes of peer point.
    :param RevCache peer_revs: Peering revocations.
    :returns: :any:`CrossOverPath`.
    """
    (up_index, down_index) = point

    up_iof, up_hofs, up_upstream_hof, up_mtu = \
        _copy_segment_shortcut(up_segment, up_index)
    down_iof, down_hofs, down_upstream_hof, down_mtu = \
        _copy_segment_shortcut(down_segment, down_index, up=False)
    up_iof.shortcut = down_iof.shortcut = True
    up_iof.peer = down_iof.peer = True
    path_metas = []
    for uph, dph, pm in _find_peer_hfs(
            up_segment.asm(up_index), down_segment.asm(down_index),
            peer_revs):
        um = min(up_mtu, pm)
        dm = min(down_mtu, pm)
        args = _shortcut_path_args(
            up_iof, up_hofs + [uph, up_upstream_hof],
            down_iof, [down_upstream_hof, dph] + down_hofs)
        path = SCIONPath.from_values(*args)
        if_list = _build_shortcut_interface_list(
            up_segment, up_index, down_segment, down_index, (uph, dph))
        mtu = _min_mtu(um, dm)
        path_meta = FwdPathMeta.from_values(path, if_list, mtu)
        path_metas.append(path_meta)
    return path_metas


def _shortcut_path_args(up_iof, up_hofs, down_iof, down_hofs):
    """
    Helper function to build args list passed to path constructor
    """
    args = []
    for iof, hofs in [(up_iof, up_hofs), (down_iof, down_hofs)]:
        l = len(hofs)
        # Any shortcut path with 2 HOFs is redundant, and can be dropped.
        if l > 2:
            iof.hops = l
            args.extend([iof, hofs])
    return args


def _build_shortcut_interface_list(
        up_seg, up_idx, down_seg, down_idx, peers=None):
    """
    Builds interface list for a shortcut path.

    :param up_seg: Up segment used in path
    :type up_seg: PathSegment
    :param up_idx: Index of peer/xovr point in up_seg
    :type up_idx: int
    :param down_seg: Down segment used in path
    :type down_seg: PathSegment
    :param down_idx: Index of peer/xovr point in down_seg
    :type down_idx: int
    :param tuple peers:
        Tuple of up segment peer HOF, down segment peer HOF
    """
    asm_list = list(reversed(list(up_seg.iter_asms(up_idx))))
    if_list = _build_interface_list(asm_list)
    if peers:
        up_peer_hof, down_peer_hof = peers
        assert up_peer_hof and down_peer_hof
        up_ia = up_seg.asm(up_idx).isd_as()
        down_ia = down_seg.asm(down_idx).isd_as()
        if_list.append(
            PathInterface.from_values(up_ia, up_peer_hof.ingress_if))
        if_list.append(
            PathInterface.from_values(down_ia, down_peer_hof.ingress_if))
    asm_list = list(down_seg.iter_asms(down_idx))
    if_list += _build_interface_list(asm_list, up=False)
    return if_list


def _build_interface_list(asms, up=True):
    """
    Builds list of interface IDs of segment ASMarkings. Order of IDs depends
    on up flag.
    """
    if_list = []
    for i, asm in enumerate(asms):
        isd_as = asm.isd_as()
        hof = asm.pcbm(0).hof()
        egress = hof.egress_if
        ingress = hof.ingress_if
        if up:
            if egress:
                if_list.append(PathInterface.from_values(isd_as, egress))
            if ingress and i != len(asms) - 1:
                if_list.append(PathInterface.from_values(isd_as, ingress))
        else:
            if ingress and i != 0:
                if_list.append(PathInterface.from_values(isd_as, ingress))
            if egress:
                if_list.append(PathInterface.from_values(isd_as, egress))
    return if_list


def _check_connected(up_segment, core_segment, down_segment):
    """
    Check if the supplied segments are connected in sequence. If the `core`
    segment is not specified, it is ignored.
    """
    if not up_segment or not down_segment:
        return True
    up_first_ia = up_segment.first_ia()
    down_first_ia = down_segment.first_ia()
    if core_segment:
        if (core_segment.last_ia() != up_first_ia or
                core_segment.first_ia() != down_first_ia):
            return False
    elif up_first_ia != down_first_ia:
        return False
    return True


def _copy_hofs(asms, reverse=True):
    """
    Copy :any:`HopOpaqueField`\s, and optionally reverse the result.

    :param list ases: List of :any:`ASMarking` objects.
    :param bool reverse: If ``True``, reverse the list before returning it.
    :returns:
        List of copied :any:`HopOpaqueField`\s.
    """
    hofs = []
    mtu = float("inf")
    for i, asm in enumerate(asms):
        pcbm = asm.pcbm(0)
        if i != 0:
            # The upstream interface's mtu is irrelevant for the first
            # ASMarking, as it won't be traversed.
            mtu = min(mtu, pcbm.p.inMTU)
        mtu = min(mtu, asm.p.mtu)
        hofs.append(pcbm.hof())
    if reverse:
        hofs.reverse()
    return hofs, mtu


def _copy_segment_shortcut(segment, index, up=True):
    """
    Copy a segment for a path shortcut, extracting the upstream
    :any:`HopOpaqueField`, and setting the `up` flag and HOF types
    appropriately.

    :param PathSegment segment: Segment to copy.
    :param int index: Index at which to start the copy.
    :param bool up:
        ``True`` if the path direction is `up` (which will reverse the
        segment direction), ``False`` otherwise (which will leave the
        segment direction unchanged).
    :returns:
        The copied :any:`InfoOpaqueField`, path :any:`HopOpaqueField`\s and
        Upstream :any:`HopOpaqueField`.
    """
    info = segment.infoF()
    info.hops -= index
    info.up_flag = up
    # Copy segment HOFs
    asms = segment.iter_asms(index)
    hofs, mtu = _copy_hofs(asms, reverse=up)
    xovr_idx = -1 if up else 0
    hofs[xovr_idx].xover = True
    # Extract upstream HOF
    upstream_hof = segment.asm(index - 1).pcbm(0).hof()
    upstream_hof.xover = False
    upstream_hof.verify_only = True
    return info, hofs, upstream_hof, mtu


def _find_peer_hfs(up_asm, down_asm, peer_revs):
    """
    Finds the peering :any:`HopOpaqueField` of the shortcut path.
    """
    hfs = []
    up_ia = up_asm.isd_as()
    down_ia = down_asm.isd_as()
    for up_peer in up_asm.iter_pcbms(1):
        up_hof = up_peer.hof()
        for down_peer in down_asm.iter_pcbms(1):
            down_hof = down_peer.hof()
            if (up_peer.inIA() == down_ia and down_peer.inIA() == up_ia and
                    up_peer.p.remoteInIF == down_hof.ingress_if and
                    up_hof.ingress_if == down_peer.p.remoteInIF):
                # Check that there is no valid revocation for the peering
                # interface.
                up_rev = peer_revs.get((up_ia, up_hof.ingress_if))
                down_rev = peer_revs.get((down_ia, down_hof.ingress_if))
                if (_skip_peer(up_rev, up_asm.p.hashTreeRoot) or
                        _skip_peer(down_rev, down_asm.p.hashTreeRoot)):
                    logging.debug(
                        "Not using peer %s:%d <-> %s:%d due to revocation."
                        % (up_ia, up_hof.ingress_if, down_ia,
                            down_hof.ingress_if))
                    continue
                hfs.append((up_hof, down_hof, up_peer.p.inMTU))
    return hfs


def _skip_peer(peer_rev, ht_root):  # pragma: no cover
    if not peer_rev:
        return False
    rev_status = ConnectedHashTree.verify_epoch(peer_rev.p.epoch)
    return (rev_status == ConnectedHashTree.EPOCH_OK and
            ConnectedHashTree.verify(peer_rev, ht_root))


def tuples_to_full_paths(tuples):
    """
    For a set of tuples of possible end-to-end path [format is:
    (up_seg, core_seg, down_seg)], return a list of fullpaths.
    """
    res = []
    for up_segment, core_segment, down_segment in tuples:
        if not up_segment and not core_segment and not down_segment:
            continue
        if not _check_connected(up_segment, core_segment,
                                down_segment):
            continue

        up_iof, up_hofs, up_mtu = _copy_segment(
            up_segment, False, (core_segment or down_segment))
        core_iof, core_hofs, core_mtu = _copy_segment(
            core_segment, up_segment, down_segment)
        down_iof, down_hofs, down_mtu = _copy_segment(
            down_segment, (up_segment or core_segment), False, up=False)
        args = []
        for iof, hofs in [(up_iof, up_hofs), (core_iof, core_hofs),
                          (down_iof, down_hofs)]:
            if iof:
                args.extend([iof, hofs])
        path = SCIONPath.from_values(*args)
        if up_segment:
            up_core = list(reversed(list(up_segment.iter_asms())))
        else:
            up_core = []
        if core_segment:
            up_core += list(reversed(list(core_segment.iter_asms())))
        if_list = _build_interface_list(up_core)
        if down_segment:
            down_core = list(down_segment.iter_asms())
        else:
            down_core = []
        if_list += _build_interface_list(down_core, up=False)
        mtu = _min_mtu(up_mtu, core_mtu, down_mtu)
        path_meta = FwdPathMeta.from_values(path, if_list, mtu)
        res.append(path_meta)
    return res


def _valid_mtu(mtu):  # pragma: no cover
    """
    Check validity of mtu value
    We assume any SCION AS supports at least the IPv6 min MTU
    """
    return mtu and mtu >= SCION_MIN_MTU


def _min_mtu(*candidates):  # pragma: no cover
    """
    Return minimum of n mtu values, checking for validity
    """
    return min(filter(_valid_mtu, candidates), default=0)
