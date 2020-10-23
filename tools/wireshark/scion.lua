scion_proto = Proto("scion", "SCION Protocol")

local pathTypes = {
    [0] = "Empty",
    [1] = "SCION",
    [2] = "OneHop",
    [3] = "EPIC",
    [4] = "COLIBRI",
}

-- This is a combination of address type and length
local addrTypes = {
    [0x0] = "IPv4", -- 0000
    [0x4] = "SVC",  -- 0100
    [0x3] = "IPv6", -- 0011
}

local hdrTypes = {
    [17] = "UDP",
    [200] = "HOP_BY_HOP",
    [201] = "END_TO_END",
    [202] = "SCMP",
    [203] = "BFD",
}

local svcTypes = {
    [0x0001] = "DS",
    [0x0002] = "CS",
    [0x0003] = "SB",
    [0x0004] = "SIG",
    [0x0005] = "HPS",
}

local flagType = {
    [0] = "Not Set",
    [1] = "Set",
}

local LINE_LEN = 4
-- Maximum SCION Hop Field TTL - one day in seconds
local HOP_MAX_TTL = 24 * 60 * 60
-- Expired time unit ~5m38s
local HOP_EXP_UNIT = HOP_MAX_TTL / 256

--local scion_raw = ProtoField.bytes("scion.raw", "Raw packet")

local scion_version = ProtoField.uint32("scion.version", "Version", base.DEC, nil, 0xf0000000)
local scion_qos = ProtoField.uint32("scion.qos", "QoS", base.HEX, nil, 0x0ff00000)
local scion_flow_id = ProtoField.uint32("scion.flow_id", "FlowID", base.HEX, nil, 0x000fffff)
local scion_next_hdr = ProtoField.uint8("scion.next_hdr", "Next Header", base.DEC, hdrTypes)
local scion_hdr_len = ProtoField.uint8("scion.hdr_len", "Header Length", base.DEC)
local scion_hdr_len_bytes = ProtoField.uint16("scion.hdr_len_bytes", "Heaer Length Bytes",
        base.UNIT_STRING, {" bytes"})
local scion_payload_len = ProtoField.uint16("scion.payload_len", "Payload Length",
        base.UNIT_STRING, {" bytes"})
local scion_path_type = ProtoField.uint8("scion.path_type", "Path Type", base.DEC, pathTypes)
--local scion_dtdlstsl = ProtoField.uint8("scion.dtdlstsl", "DT_DL_ST_SL", base.HEX)
local scion_dst_type_len = ProtoField.uint8("scion.dst_type_len", "Destination Type",
        base.HEX, addrTypes, 0xf0)
local scion_src_type_len = ProtoField.uint8("scion.src_type_len", "Source Type",
        base.HEX, addrTypes, 0x0f)
local scion_rsv = ProtoField.uint16("scion.rsv", "Reserved", base.HEX)

local scion_dst_isd = ProtoField.uint16("scion.dst_isd", "Destination ISD", base.DEC)
--local scion_dst_as_raw = ProtoField.bytes("scion.dst_as_raw", "Raw Destination AS", base.SPACE)
local scion_dst_as = ProtoField.string("scion.dst_as", "Destination AS")
local scion_src_isd = ProtoField.uint16("scion.src_isd", "Source ISD", base.DEC)
--local scion_src_as_raw = ProtoField.bytes("scion.src_as_raw", "Raw Source AS", base.SPACE)
local scion_src_as = ProtoField.string("scion.src_as", "Source AS")

local scion_dst_host = ProtoField.string("scion.dst_host", "Destination Host")
local scion_src_host = ProtoField.string("scion.src_host", "Source Host")
local scion_dst_host_raw = ProtoField.bytes("scion.dst_host", "Raw Destination Host", base.SPACE)
local scion_src_host_raw = ProtoField.bytes("scion.src_host", "Raw Source Host", base.SPACE)
local scion_dst = ProtoField.string("scion.dst", "Destination")
local scion_src = ProtoField.string("scion.src", "Source")

scion_proto.fields = {
    scion_raw,

    scion_version,
    scion_qos,
    scion_flow_id,
    scion_next_hdr,
    scion_hdr_len,
    scion_hdr_len_bytes,
    scion_payload_len,
    scion_path_type,
    --scion_dtdlstsl,
    scion_dst_type_len,
    scion_src_type_len,
    scion_rsv,

    scion_dst_isd,
    --scion_dst_as_raw,
    scion_dst_as,
    scion_src_isd,
    --scion_src_as_raw,
    scion_src_as,

    scion_dst_host,
    scion_src_host,
    scion_dst_host_raw,
    scion_src_host_raw,
    scion_dst,
    scion_src,
}

-- XXX(sgmonroy) are these expert worth it? AFAICS the parser would emit a Lua error,
-- plus its own expert in case of failing to parse, ie. throwing index out of bounds 
-- when the packet is too short/truncated.
-- Maybe just do expert for some important errors worth of spotting quickly
local e_nosup_ver = ProtoExpert.new("scion.nosup_ver.expert",
        "Unsupported version", expert.group.UNDECODED, expert.severity.ERROR)
local e_too_short = ProtoExpert.new("scion.too_short.expert",
        "Packet too short", expert.group.MALFORMED, expert.severity.ERROR)
local e_bad_len = ProtoExpert.new("scion.bad_len.expert",
        "Bad packet length", expert.group.MALFORMED, expert.severity.ERROR)
local e_bad_src_addr_expert = ProtoExpert.new("scion.bad_src_addr.expert",
        "Unknown address type", expert.group.PROTOCOL, expert.severity.ERROR)
local e_nosup_proto = ProtoExpert.new("scion.nosup_proto.expert",
        "Unsupported protocol", expert.group.UNDECODED, expert.severity.ERROR)

scion_proto.experts = {
    e_nosup_ver,
    e_too_short,
    e_bad_len,
    e_bad_src_addr_expert,
    e_nosup_proto,
}

function scion_proto.dissector(tvbuf, pktinfo, root)
    local tree = root:add(scion_proto, tvbuf())
    local header_str = tree
    local scion = {}

    -- Minimum length for SCION header without path and without payload is 36 bytes:
    --  12 (common ) + 16 (src/dst ISD-AS) + 8 (src/dst addr 4B each)
    if tvbuf:len() < 36 then
        tree:add_proto_expert_info(e_too_short)
        return
    end

    local version = bit.rshift(tvbuf(0,1):uint(), 4)
    if version ~= 0 then
        tree:add_tvb_proto_expert_info(e_nosup_ver, tvbuf(0,1))
        return
    end

    tree:add(scion_version, tvbuf(0, 4))
    tree:add(scion_qos, tvbuf(0, 4))
    tree:add(scion_flow_id, tvbuf(0, 4))

    scion["next_hdr"] = tvbuf(4, 1)
    tree:add(scion_next_hdr, scion.next_hdr)

    -- TODO Is there a better way to show:
    -- Header Length: 72 bytes (18)
    scion["hdr_len"] = tvbuf(5, 1)
    local hdr_len = scion.hdr_len:uint()
    scion["len_bytes"] = hdr_len * LINE_LEN
    local str = string.format("Header Length: %d bytes (%d)", scion.len_bytes, hdr_len)
    tree:add(scion_hdr_len, tvbuf(5, 1)):set_text(str)

    scion["payload_len"] = tvbuf(6, 2)
    tree:add(scion_payload_len, scion.payload_len)

    scion["path_type"] = pathTypes[tvbuf(8, 1):uint()]
    tree:add(scion_path_type, tvbuf(8, 1))

    scion["dst_type_len"] = tvbuf(9, 1):bitfield(0, 4)
    tree:add(scion_dst_type_len, tvbuf(9, 1))
    scion["src_type_len"] = tvbuf(9, 1):bitfield(4, 4)
    tree:add(scion_src_type_len, tvbuf(9, 1))

    tree:add(scion_rsv, tvbuf(10, 2))

    -- Destination address: ISD, AS
    scion["dst_isd"] = tvbuf(12, 2)
    tree:add(scion_dst_isd, scion.dst_isd)
    scion["dst_as"] = tvbuf(14, 6)
    tree:add(scion_dst_as, as_str(scion.dst_as))

    -- Source address: ISD, AS
    scion["src_isd"] = tvbuf(20, 2)
    tree:add(scion_src_isd, scion.src_isd)
    scion["src_as"] = tvbuf(22, 6)
    tree:add(scion_src_as, as_str(scion.src_as))

    local path_offset = 28 + addr_len(scion.dst_type_len) + addr_len(scion.src_type_len)
    if tvbuf:len() < path_offset then
        tree:add_proto_expert_info(e_too_short)
        return
    end

    -- Destination host
    local addrBuf = tvbuf(28, addr_len(scion.dst_type_len))
    --tree:add(scion_dst_host_raw, addrBuf)
    local dst_host_str = addr_str(addrBuf, scion.dst_type_len, true)
    tree:add(scion_dst_host, addrBuf, dst_host_str)

    -- Source host
    addrBuf = tvbuf(28 + addr_len(scion.dst_type_len), addr_len(scion.src_type_len))
    --tree:add(scion_src_host_raw, addrBuf)
    local src_host_str = addr_str(addrBuf, scion.src_type_len, false)
    tree:add(scion_src_host, addrBuf, src_host_str)

    scion["dst"] = scion_addr_str(scion.dst_isd, scion.dst_as, dst_host_str)
    scion["src"] = scion_addr_str(scion.src_isd, scion.src_as, src_host_str)
    header_str:append_text(string.format(", Src: %s, Dst: %s", scion.src, scion.dst))

    --pktinfo.cols.protocol:set("SCION")
    pktinfo.cols.info:append(string.format(" SCION %s -> %s %s", scion.src, scion.dst,
            hdrTypes[scion.next_hdr:uint()]))

    if tvbuf:len() ~= scion.len_bytes + scion.payload_len:uint() then
        tree:add_tvb_expert_info(e_bad_len, tvbuf(5, 3))
    end

    if tvbuf:len() < scion.len_bytes then
        tree:add_tvb_expert_info(e_too_short, scion.hdr_len)
        scion["len_bytes"] = tvbuf:len()
    end

    if scion.path_type == "SCION" then
        --scion_path_dissect(tvbuf(path_offset), pktinfo, tree)
        ok = scion_path_dissect(tvbuf(path_offset), pktinfo, tree)
        if not ok then
            return
        end
    end
    if scion.path_type == "OneHop" then
        scion_ohp_dissect(tvbuf(path_offset), pktinfo, tree)
    end

    -- TODO Extensions

    local next_proto = hdrTypes[scion.next_hdr:uint()]
    if next_proto == "UDP" then
        scion_udp_proto_dissect(tvbuf(scion.len_bytes, 8), pktinfo, root)
    end
    if next_proto == "SCMP" then
        scmp_proto_dissect(tvbuf(scion.len_bytes), pktinfo, root)
    end
    if next_proto == "BFD" then
        Dissector.get("bfd"):call(tvbuf(scion.len_bytes):tvb(), pktinfo, root)
    end

end

function as_str(as)
    local asDec = as:uint64():tonumber()
    if asDec <= 0xffffffff then
        return string.format("%d", asDec)
    end
    return string.format("%x:%x:%x", as(0, 2):uint(), as(2, 2):uint(), as(4, 2):uint())
end

function isd_as_str(isd, as)
    return string.format("%d-%s", isd:uint(), as_str(as))
end

function scion_addr_str(isd, as, host)
    return string.format("%d-%s,[%s]", isd:uint(), as_str(as), host)
end

function addr_str(buf, addrTypeLen, with_svc)
    local addrType = addrTypes[addrTypeLen]
    if addrType == "IPv4" then
        return string.format("%s", buf:ipv4())
    elseif addrType == "IPv6" then
        return string.format("%s", buf:ipv6())
    elseif with_svc and addrType == "SVC" then
        local svcVal = buf(0, 2):uint()
        local svc = svcTypes[svcVal]
        if svc == nil then
            return string.format("Unknown (%d)", svcVal)
        end
        return string.format("%s (%d)", svc, svcVal)
        -- TODO check that buf(2, 2) is zeroed
    end
    return string.format("%s", buf)
end

function addr_len(addr)
    return (bit.band(addr, 0x3) + 1) * LINE_LEN
end

-- One Hop Path
scion_ohp = Proto("scion_ohp", "One Hop Path")

function scion_ohp_dissect(tvbuf, pktinfo, root)
    local seg_hops = scion_path_seg_lens(tvbuf(0, 4), 0)

    local ts = scion_path_info_dissect(tvbuf(0, 8), pktinfo, root, 0)
    scion_path_hop_dissect(tvbuf(8, 12), pktinfo, root, 0, ts)
    scion_path_hop_dissect(tvbuf(20, 12), pktinfo, root, 1, ts)
end

-- SCION Path
scion_path = Proto("scion_path", "SCION Path")

-- SCION Path Meta fields
local spath_curr_info = ProtoField.uint32("scion_path.curr_info", "Current Info Field",
        base.DEC, nil, 0xc0000000)
local spath_curr_hop = ProtoField.uint32("scion_path.curr_hop", "Current Hop Field",
        base.DEC, nil, 0x3f000000)
local spath_rsv = ProtoField.uint32("scion_path.rsv", "Reserved",
        base.DEC, nil, 0x00fc0000)
local spath_seg0_len = ProtoField.uint32("scion_path.seg0_len", "Segment 0 Length",
        base.DEC, nil, 0x0003f000)
local spath_seg1_len = ProtoField.uint32("scion_path.seg1_len", "Segment 1 Length",
        base.DEC, nil, 0x00000fc0)
local spath_seg2_len = ProtoField.uint32("scion_path.seg2_len", "Segment 2 Length",
        base.DEC, nil, 0x0000003f)
-- SCION Path Info fields
local spath_info_flags = ProtoField.uint8("scion_path.info.flags", "Flags", base.HEX)
local spath_info_flag_consdir = ProtoField.uint8("scion_path.info.flag_consdir", "ConsDir",
        base.HEX, flagType, 0x1)
local spath_info_flag_peer = ProtoField.uint8("scion_path.info.flag_peer", "Peer",
        base.HEX, flagType, 0x2)
local spath_info_rsv = ProtoField.uint8("scion_path.info.rsv", "Reserved", base.HEX)
local spath_info_seg_id = ProtoField.uint16("scion_path.info.seg_id", "Segment ID", base.HEX)
local spath_info_ts = ProtoField.absolute_time("scion_path.info.ts", "Timestamp", base.UTC)
-- SCION Path Hop fields
local spath_hop_flags = ProtoField.uint8("scion_path.hop.flags", "Flags", base.HEX)
local spath_hop_flag_in_alert = ProtoField.uint8("scion_path.hop.flag_in_alert",
        "ConsIngress Router Alert", base.HEX, flagType, 0x2)
local spath_hop_flag_eg_alert = ProtoField.uint8("scion_path.hop.flag_eg_alert",
        "ConsEgress Router Alert", base.HEX, flagType, 0x1)
local spath_hop_exp = ProtoField.uint8("scion_path.hop.expiry", "Expiry", base.DEC)
local spath_hop_exp_rel = ProtoField.relative_time("scion_path.hop.expiry_rel",
        "Expiry (Relative)", base.UTC)
local spath_hop_exp_abs = ProtoField.absolute_time("scion_path.hop.expiry_abs",
        "Expiry (Absolute)", base.UTC)
local spath_hop_cons_ingress = ProtoField.uint16("scion_path.hop.cons_ingress",
        "ConsIngress IFID", base.DEC)
local spath_hop_cons_egress = ProtoField.uint16("scion_path.hop.cons_egress",
        "ConsEgress IFID", base.DEC)
local spath_hop_mac = ProtoField.bytes("scion_path.hop.mac", "MAC")

scion_path.fields = {
    spath_curr_info,
    spath_curr_hop,
    spath_rsv,
    spath_seg0_len,
    spath_seg1_len,
    spath_seg2_len,

    spath_info_flags,
    spath_info_flag_consdir,
    spath_info_flag_peer,
    spath_info_rsv,
    spath_info_seg_id,
    spath_info_ts,

    spath_hop_flags,
    spath_hop_flag_in_alert,
    spath_hop_flag_eg_alert,
    spath_hop_exp,
    spath_hop_exp_rel,
    spath_hop_exp_abs,
    spath_hop_cons_ingress,
    spath_hop_cons_egress,
    spath_hop_mac,
}

function scion_path_dissect(tvbuf, pktinfo, root)
    --local tree = root:add(scion_path, tvbuf())
    local tree = root:add(scion_path, tvbuf()):set_text("Path Meta")

    tree:add(spath_curr_info, tvbuf(0, 4))
    tree:add(spath_curr_hop, tvbuf(0, 4))
    tree:add(spath_rsv, tvbuf(0, 4))
    tree:add(spath_seg0_len, tvbuf(0, 4))
    tree:add(spath_seg1_len, tvbuf(0, 4))
    tree:add(spath_seg2_len, tvbuf(0, 4))

    local seg0_hops = scion_path_seg_lens(tvbuf(0, 4), 0)
    local seg1_hops = scion_path_seg_lens(tvbuf(0, 4), 1)
    local seg2_hops = scion_path_seg_lens(tvbuf(0, 4), 2)

    local seg0_ts = scion_path_info_dissect(tvbuf(4, 8), pktinfo, root, 0)
    local seg1_ts
    local seg2_ts
    local offset = 12
    if seg1_hops > 0 then
        seg1_ts = scion_path_info_dissect(tvbuf(offset, 8), pktinfo, root, 1)
        offset = offset + 8
    end
    if seg2_hops > 0 then
        seg2_ts = scion_path_info_dissect(tvbuf(offset, 8), pktinfo, root, 2)
        offset = offset + 8
    end
    local n_hops = seg0_hops + seg1_hops + seg2_hops
    local ts
    for i=0,n_hops-1 do
        if i < seg0_hops then
            ts = seg0_ts
        elseif i < seg0_hops + seg1_hops then
            ts = seg1_ts
        else
            ts = seg2_ts
        end
        scion_path_hop_dissect(tvbuf(offset, 12), pktinfo, root, i, ts)
        offset = offset + 12
    end

    return true
end

function scion_path_info_dissect(tvbuf, pktinfo, root, index)
    local tree = root:add(tvbuf, "Info Field", index)

    tree:add(spath_info_flags, tvbuf(0, 1))
    tree:add(spath_info_flag_consdir, tvbuf(0, 1))
    tree:add(spath_info_flag_peer, tvbuf(0, 1))
    tree:add(spath_info_rsv, tvbuf(1, 1))
    tree:add(spath_info_seg_id, tvbuf(2, 2))
    tree:add(spath_info_ts, tvbuf(4, 4))

    return tvbuf(4, 4)
end

function scion_path_hop_dissect(tvbuf, pktinfo, root, index, ts)
    local tree = root:add(tvbuf, "Hop Field", index)

    tree:add(spath_hop_flags, tvbuf(0, 1))
    tree:add(spath_hop_flag_in_alert, tvbuf(0, 1))
    tree:add(spath_hop_flag_eg_alert, tvbuf(0, 1))
    tree:add(spath_hop_exp, tvbuf(1, 1))
    local raw_exp_time = (tvbuf(1, 1):uint() + 1) * HOP_EXP_UNIT
    tree:add(spath_hop_exp_rel, tvbuf(1, 1), NSTime.new(raw_exp_time))
    tree:add(spath_hop_exp_abs, tvbuf(1, 1), NSTime.new((raw_exp_time) + ts:uint()))
    tree:add(spath_hop_cons_ingress, tvbuf(2, 2))
    tree:add(spath_hop_cons_egress, tvbuf(4, 2))
    tree:add(spath_hop_mac, tvbuf(6, 6))
end

function scion_path_seg_lens(tvbuf, index)
    return bit.band(bit.rshift(tvbuf:uint(), (12 - (6 * index))), 0x3f)
end


-- SCION UDP
-- We re-implement UDP here because the checksum calculation with SCION is different.
scion_udp_proto = Proto("scion_udp", "SCION User Datagram Protocol")

local udp_src_port = ProtoField.uint16("scion_udp.src_port", "Source Port", base.DEC)
local udp_dst_port = ProtoField.uint16("scion_udp.dst_port", "Destination Port", base.DEC)
local udp_length = ProtoField.uint16("scion_udp.length", "Length", base.DEC)
local udp_cksum = ProtoField.uint16("scion_udp.cksum", "Checksum", base.HEX)

scion_udp_proto.fields = {
    udp_src_port,
    udp_dst_port,
    udp_length,
    udp_cksum,
}

function scion_udp_proto_dissect(tvbuf, pktinfo, root)
    local tree = root:add(scion_udp_proto, tvbuf())

    local udp = {}

    udp["src_port"] = tvbuf(0, 2)
    udp["dst_port"] = tvbuf(2, 2)
    udp["length"] = tvbuf(4, 2)
    udp["cksum"] = tvbuf(6, 2)

    tree:append_text(string.format(", Src Port: %s, Dst Port: %s", udp.src_port:uint(),
                            udp.dst_port:uint()))

    pktinfo.cols.info:append(string.format(" %d -> %d %d", udp.src_port:uint(),
                             udp.dst_port:uint(), udp.length:uint()))

    tree:add(udp_src_port, udp.src_port)
    tree:add(udp_dst_port, udp.dst_port)
    tree:add(udp_length, udp.length)
    -- TODO SCION/UDP checksum validation
    tree:add(udp_cksum, udp.cksum):append_text(" [unverified]")
end


-- SCMP
scmp_proto = Proto("scmp", "SCION Control Message Protocol")

local scmpDstUnreachCodes = {
    [0] = "No route to destination",
    [1] = "Communication administratively denied",
    [2] = "Beyond scope of source address",
    [3] = "Address unreachable",
    [4] = "Port unreachable",
    [5] = "Source address failed ingress/egress policy",
    [6] = "Reject route to destination",
}

local scmpPktTooBigCodes = {
    [0] = "Packet too big",
}

local scmpParamProblemCodes = {
    [0] = "Erroneous header field",
    [1] = "Unknown next-hdr type",
    [2] = "unassigned",
    [16] = "Invalid common header",
    [17] = "Unknown SCION version",
    [18] = "Flow ID required",
    [19] = "Invalid packet size",
    [20] = "Unknown path type",
    [21] = "Unknown address format",
    [32] = "Invalid address header",
    [33] = "Invalid source address",
    [34] = "Invalid destination address",
    [35] = "Non-local delivery",
    [48] = "Invalid path",
    [49] = "Unknown hop field cons ingress interface",
    [50] = "Unknown hop field cons egress interface",
    [51] = "Invalid hop field MAC",
    [52] = "Path expired",
    [53] = "Invalid segment change",
    [64] = "Invalid extension header",
    [65] = "Unknown hop-by-hop option",
    [66] = "Unknown end-to-end option",
}

local scmpInterfaceDownCodes = {
    [0] = "External interface Down",
}

local scmpConnDownCodes = {
    [0] = "Internal connectivity down",
}

local scmpErrorPriv1Codes = {
    [0] = "Error Private1",
}

local scmpErrorPriv2Codes = {
    [0] = "Error Private2",
}

local scmpErrorRsvCodes = {
    [0] = "Error Reserved",
}

local scmpEchoReqCodes = {
    [0] = "Echo request",
}

local scmpEchoReplyCodes = {
    [0] = "Echo reply",
}

local scmpTracerouteReqCodes = {
    [0] = "Traceroute request",
}

local scmpTracerouteReplyCodes = {
    [0] = "Traceroute reply",
}

local scmpInfoPriv1Codes = {
    [0] = "Info Private1",
}

local scmpInfoPriv2Codes = {
    [0] = "Info Private2",
}

local scmpInfoRsvCodes = {
    [0] = "Info Reserved",
}

local scmpTypes = {
    [1] = scmpDstUnreachCodes,
    [2] = scmpPktTooBigCodes,
    [4] = scmpParamProblemCodes,
    [5] = scmpInterfaceDownCodes,
    [6] = scmpConnDownCodes,
    [100] = scmpErrorPriv1Codes,
    [101] = scmpErrorPriv2Codes,
    [127] = scmpErrorRsvCodes,
    [128] = scmpEchoReqCodes,
    [129] = scmpEchoReplyCodes,
    [130] = scmpTracerouteReqCodes,
    [131] = scmpTracerouteReplyCodes,
    [200] = scmpInfoPriv1Codes,
    [201] = scmpInfoPriv2Codes,
    [255] = scmpInfoRsvCodes,
}

local scmp_type = ProtoField.uint8("scmp.type", "Type", base.DEC)
local scmp_code = ProtoField.uint8("scmp.code", "Code", base.DEC)
local scmp_cksum = ProtoField.uint16("scmp.cksum", "Checksum", base.HEX)
local scmp_mtu = ProtoField.uint16("scmp.mtu", "MTU", base.DEC)
local scmp_pointer = ProtoField.uint16("scmp.pointer", "Pointer", base.DEC)
local scmp_isd = ProtoField.uint16("scmp.isd", "ISD", base.DEC)
local scmp_as = ProtoField.string("scmp.as", "AS")
local scmp_ifid = ProtoField.uint64("scmp.ifid", "IFID", base.DEC)
local scmp_ifid_in = ProtoField.uint64("scmp.ifid_in", "Ingress IFID", base.DEC)
local scmp_ifid_eg = ProtoField.uint64("scmp.ifid_eg", "Egress IFID", base.DEC)
local scmp_id = ProtoField.uint16("scmp.id", "Identifier", base.DEC)
local scmp_seq = ProtoField.uint16("scmp.seq", "Sequence Number", base.DEC)
local scmp_raw = ProtoField.bytes("scmp.raw", "Raw SCMP")

scmp_proto.fields = {
    scmp_type,
    scmp_code,
    scmp_cksum,
    scmp_mtu,
    scmp_pointer,
    scmp_isd,
    scmp_as,
    scmp_ifid,
    scmp_ifid_in,
    scmp_ifid_eg,
    scmp_id,
    scmp_seq,
    scmp_raw,
}

function scmp_proto_dissect(tvbuf, pktinfo, root)
    local tree = root:add(scmp_proto, tvbuf())

    local scmp = {}

    scmp["type"] = tvbuf(0, 1)
    scmp["code"] = tvbuf(1, 1)

    tree:add(scmp_type, scmp.type)
    tree:add(scmp_code, scmp.code)
    tree:add(scmp_cksum, tvbuf(2, 2)):append_text(" [unverified]")

    local codes = scmpTypes[scmp.type:uint()]
    if codes == nil then
        tree:append_text(", Unknown Type")
        return
    end

    local data_offset = 8
    if codes == scmpPktTooBigCodes then
        tree:add(scmp_mtu, tvbuf(6, 2))
    end
    if codes == scmpParamProblemCodes then
        tree:add(scmp_pointer, tvbuf(6, 2))
    end
    if codes == scmpInterfaceDownCodes then
        tree:add(scmp_isd, tvbuf(4, 2))
        tree:add(scmp_as, as_str(tvbuf(6, 6)))
        tree:add(scmp_ifid, tvbuf(12, 8))
        scmp["append_str"] = string.format("ISD-AS: %s, IFID: %d",
                isd_as_str(tvbuf(4, 2), tvbuf(6, 6)), tvbuf(12, 8):uint64():tonumber())
        data_offset = 20
    end
    if codes == scmpConnDownCodes then
        tree:add(scmp_isd, tvbuf(4, 2))
        tree:add(scmp_as, as_str(tvbuf(6, 6)))
        tree:add(scmp_ifid_in, tvbuf(12, 8))
        tree:add(scmp_ifid_eg, tvbuf(20, 8))
        scmp["append_str"] = string.format("ISD-AS: %s, IFIDs: %d | %d",
                isd_as_str(tvbuf(4, 2), tvbuf(6, 6)),
                tvbuf(12, 8):uint():tonumber(), tvbuf(20, 8):uint64():tonumber())
        data_offset = 28
    end
    if codes == scmpEchoReqCodes or codes == scmpEchoReplyCodes then
        tree:add(scmp_id, tvbuf(4, 2))
        tree:add(scmp_seq, tvbuf(6, 2))
    end
    if codes == scmpTracerouteReqCodes then
        tree:add(scmp_id, tvbuf(4, 2))
        tree:add(scmp_seq, tvbuf(6, 2))
    end
    if codes == scmpTracerouteReplyCodes then
        tree:add(scmp_id, tvbuf(4, 2))
        tree:add(scmp_seq, tvbuf(6, 2))
        tree:add(scmp_isd, tvbuf(8, 2))
        tree:add(scmp_as, as_str(tvbuf(10, 6)))
        tree:add(scmp_ifid, tvbuf(16, 8))
        scmp["append_str"] = string.format("ISD-AS: %s, IFID: %d",
                isd_as_str(tvbuf(8, 2), tvbuf(10, 6)), tvbuf(16, 8):uint64():tonumber())
    end

    local code = codes[scmp.code:uint()]
    if code == nil then
        tree:append_text(", Unknown Code")
        return
    end
    tree:append_text(string.format(", %s", code))
    if scmp.append_str ~= nil then
        tree:append_text(string.format(", %s", scmp.append_str))
    end
    if scmp.type:uint() < 128 then
        -- try to parse quoted packet
        scion_proto.dissector(tvbuf(data_offset):tvb(), pktinfo, tree)
    end
end


-- Below we configure Wireshark to identify SCION as the next protocol when using
-- the specified range of ports.
--
-- SCION packet on UDP/IP overlay.
table_udp = DissectorTable.get("udp.port")
-- intra-AS traffic
for i = 30000, 32000, 1 do
    table_udp:add(i, scion_proto)
end
-- inter-AS BR traffic
for i = 40000, 40050, 1 do
    table_udp:add(i, scion_proto)
end
-- FIXME remove once acceptance tests are updated to use ports above
-- acceptance tests
for i = 50000, 50050, 1 do
    table_udp:add(i, scion_proto)
end
