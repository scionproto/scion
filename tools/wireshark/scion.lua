scion_proto = Proto("scion", "SCION", "SCION Protocol")

local addrTypes = {
    [0] = "None",
    [1] = "IPv4",
    [2] = "IPv6",
    [3] = "SVC",
}
local addrLens = {
    ["None"] = 0,
    ["IPv4"] = 4,
    ["IPv6"] = 16,
    ["SVC"] = 2,
}
local hdrTypes = {
    [0] = "None/Hopbyhop",
    [1] = "SCMP",
    [6] = "TCP",
    [17] = "UDP",
    [222] = "End2End",
}
local svcTypes = {
    [0x0000] = "BS_A (Anycast)",
    [0x0001] = "PS_A (Anycast)",
    [0x0002] = "CS_A (Anycast)",
    [0x0003] = "SB_A (Anycast)",
    [0x8000] = "BS_M (Multicast)",
    [0x8001] = "PS_M (Multicast)",
    [0x8002] = "CS_M (Multicast)",
    [0x8003] = "SB_M (Multicast)",
    [0xffff] = "None",
}
local chLen = 8
local lineLen = 8
local iaLen = 4
local maxSegTTL = 12 * 60 * 60
local segExpUnit = maxSegTTL / 2^8

local scion_ch_version = ProtoField.uint8("scion.ch.version", "Version", base.HEX)
local scion_ch_dsttype = ProtoField.uint8("scion.ch.dst_type", "Destination address type", base.HEX, addrTypes)
local scion_ch_srctype = ProtoField.uint8("scion.ch.src_type", "Source address type", base.HEX, addrTypes)
local scion_ch_totallen = ProtoField.uint16("scion.ch.total_len", "Total length", base.DEC)
local scion_ch_hdrlen = ProtoField.uint8("scion.ch.hdr_len", "Header length", base.DEC)
local scion_ch_infoff = ProtoField.uint8("scion.ch.inf_off", "Info Field offset", base.DEC)
local scion_ch_hopoff = ProtoField.uint8("scion.ch.hop_off", "Hop Field offset", base.DEC)
local scion_ch_nexthdr = ProtoField.uint8("scion.ch.next_hdr", "Next header", base.DEC, hdrTypes)

local scion_addr_dst_isd = ProtoField.uint8("scion.addr.dst_isd", "Dest ISD", base.DEC)
local scion_addr_dst_as = ProtoField.uint8("scion.addr.dst_as", "Dest AS", base.DEC)
local scion_addr_src_isd = ProtoField.uint8("scion.addr.src_isd", "Src ISD", base.DEC)
local scion_addr_src_as = ProtoField.uint8("scion.addr.src_as", "Src AS", base.DEC)
local scion_addr_dst_ipv4 = ProtoField.ipv4("scion.addr.dst_ipv4", "Dest IPv4")
local scion_addr_dst_ipv6 = ProtoField.ipv6("scion.addr.dst_ipv6", "Dest IPv6")
local scion_addr_dst_svc = ProtoField.uint16("scion.addr.dst_svc", "Dest SVC", base.HEX, svcTypes)
local scion_addr_src_ipv4 = ProtoField.ipv4("scion.addr.src_ipv4", "Src IPv4")
local scion_addr_src_ipv6 = ProtoField.ipv6("scion.addr.src_ipv6", "Src IPv6")
local scion_addr_padding = ProtoField.bytes("scion.addr.padding", "Padding")

local scion_path_info_flags = ProtoField.uint8("scion.path.info.flags", "Flags", base.HEX)
local scion_path_info_flags_peer = ProtoField.bool("scion.path.info.flags.peer",
    "Peer", 8, nil, 0x4)
local scion_path_info_flags_shortcut = ProtoField.bool("scion.path.info.flags.shortcut",
    "Shortcut", 8, nil, 0x2)
local scion_path_info_flags_up = ProtoField.bool("scion.path.info.flags.up",
    "Up", 8, nil, 0x1)
-- XXX(kormat): This *should* be base.UTC, but that seems to be bugged in ubuntu 16.04's
-- version of wireshark. Amazingly, using the raw enum value works.
-- https://github.com/wireshark/wireshark/blob/2832f4e97d77324b4e46aac40dae0ce898ae559d/epan/time_fmt.h#L44
local scion_path_info_ts = ProtoField.absolute_time("scion.path.info.ts", "Timestamp", 1001)
local scion_path_info_isd = ProtoField.uint16("scion.path.info.isd", "ISD", base.DEC)
local scion_path_info_hops = ProtoField.uint8("scion.path.info.hops", "Hops", base.DEC)

local scion_path_hop_flags = ProtoField.uint8("scion.path.hop.flags", "Flags", base.HEX)
local scion_path_hop_flags_recurse = ProtoField.bool("scion.path.hop.flags.recurse",
    "Recurse", 8, nil, 0x8)
local scion_path_hop_flags_fwdonly = ProtoField.bool("scion.path.hop.flags.fwdonly",
    "Forward-Only", 8, nil, 0x4)
local scion_path_hop_flags_verifyonly = ProtoField.bool("scion.path.hop.flags.verifyonly",
    "Verify-Only", 8, nil, 0x2)
local scion_path_hop_flags_xover = ProtoField.bool("scion.path.hop.flags.xover",
    "Xover", 8, nil, 0x1)
local scion_path_hop_exp_raw = ProtoField.uint8("scion.path.hop.expiry_raw", "Expiry (Raw)", base.DEC)
local scion_path_hop_exp_rel = ProtoField.relative_time("scion.path.hop.expiry_rel", "Expiry (Relative)", 1001)
local scion_path_hop_exp_abs = ProtoField.absolute_time("scion.path.hop.expiry_abs", "Expiry (Absolute)", 1001)
local scion_path_hop_ingress_if = ProtoField.uint64("scion.path.hop.ingress_if",
    "Ingress IFID", base.DEC)
local scion_path_hop_egress_if = ProtoField.uint64("scion.path.hop.egress_if",
    "Egress IFID", base.DEC)
local scion_path_hop_mac = ProtoField.bytes("scion.path.hop.mac", "MAC", base.HEX)

local scion_ch_ver_expert = ProtoExpert.new("scion.ch.version.expert",
    "Unsupported SCION version", expert.group.MALFORMED, expert.severity.ERROR)
local scion_ch_addrtype_expert = ProtoExpert.new("scion.ch.addr_type.expert",
    "", expert.group.MALFORMED, expert.severity.ERROR)
local scion_ch_totallen_expert = ProtoExpert.new("scion.ch.total_len.expert",
    "", expert.group.MALFORMED, expert.severity.ERROR)
local scion_ch_hdrlen_expert = ProtoExpert.new("scion.ch.hdr_len.expert",
    "", expert.group.MALFORMED, expert.severity.ERROR)
local scion_ch_infoff_expert = ProtoExpert.new("scion.ch.inf_off.expert",
    "", expert.group.MALFORMED, expert.severity.ERROR)
local scion_ch_hopoff_expert = ProtoExpert.new("scion.ch.hop_off.expert",
    "", expert.group.MALFORMED, expert.severity.ERROR)

scion_proto.fields={
    scion_ch_version,
    scion_ch_dsttype,
    scion_ch_srctype,
    scion_ch_totallen,
    scion_ch_hdrlen,
    scion_ch_infoff,
    scion_ch_hopoff,
    scion_ch_nexthdr,
    scion_addr_dst_isd,
    scion_addr_dst_as,
    scion_addr_src_isd,
    scion_addr_src_as,
    scion_addr_dst_ipv4,
    scion_addr_dst_ipv6,
    scion_addr_dst_svc,
    scion_addr_src_ipv4,
    scion_addr_src_ipv6,
    scion_addr_padding,
    scion_path_info_flags,
    scion_path_info_flags_peer,
    scion_path_info_flags_shortcut,
    scion_path_info_flags_up,
    scion_path_info_ts,
    scion_path_info_isd,
    scion_path_info_hops,
    scion_path_hop_flags,
    scion_path_hop_flags_recurse,
    scion_path_hop_flags_fwdonly,
    scion_path_hop_flags_verifyonly,
    scion_path_hop_flags_xover,
    scion_path_hop_exp_raw,
    scion_path_hop_exp_rel,
    scion_path_hop_exp_abs,
    scion_path_hop_ingress_if,
    scion_path_hop_egress_if,
    scion_path_hop_mac,
}

scion_proto.experts = {
    scion_ch_ver_expert,
    scion_ch_addrtype_expert,
    scion_ch_totallen_expert,
    scion_ch_hdrlen_expert,
    scion_ch_infoff_expert,
    scion_ch_hopoff_expert,
}


function scion_proto.dissector(buffer, pinfo, root)
    pinfo.cols.protocol = "SCION"
    local tree = root:add(scion_proto, buffer(), "SCION Protocol")
    local ch, meta = parse_cmn_hdr(buffer(0, chLen), tree, buffer:len())
    if ch == nil or meta == nil then
        return
    end
    parse_addr_hdr(buffer(chLen, meta.addrTotalLen), tree, meta)
    if meta.pathLen > 0 then
        parse_path_hdr(buffer(meta.pathOffset, meta.pathLen), tree, meta)
    end
end

function parse_cmn_hdr(buffer, tree, pktlen)
    local ch = {}  -- Direct representation of Common Header
    local meta = {}  -- Values derived from common header
    local t = tree:add(buffer, "Common header [8B]")
    -- scion version
    ch["ver"] = buffer(0, 1):bitfield(0, 4)
    local subt = t:add(scion_ch_version, buffer(0, 1), ch.ver)
    if ch.ver ~= 0 then
        subt:add_tvb_expert_info(scion_ch_ver_expert, buffer(0, 1))
        return
    end
    -- destination address type
    ch["rawDstType"] = buffer(0, 2):bitfield(4, 6)
    meta["dstType"] = addrTypes[ch.rawDstType]
    subt = t:add(scion_ch_dsttype, buffer(0, 2), ch.rawDstType)
    if meta.dstType == nil then
        subt:add_tvb_expert_info(scion_ch_addrtype_expert, buffer(0, 2),
            "Unknown destination address type")
    end
    -- source address type
    ch["rawSrcType"] = buffer(1, 1):bitfield(2, 6)
    meta["srcType"] = addrTypes[ch.rawSrcType]
    subt = t:add(scion_ch_srctype, buffer(1, 1), ch.rawSrcType)
    if meta.srcType == "SVC" then
        subt:add_tvb_expert_info(scion_ch_addrtype_expert, buffer(0, 2), "Illegal source address type")
    elseif meta.srcType == nil then
        subt:add_tvb_expert_info(scion_ch_addrtype_expert, buffer(0, 2), "Unknown source address type")
    end
    -- addr header length
    meta["addrLen"] = 2 * iaLen + addrLens[meta.dstType] + addrLens[meta.srcType]
    meta["addrPadding"] = calc_padding(meta.addrLen, lineLen)
    meta["addrTotalLen"] = meta.addrLen + meta.addrPadding
    -- total length
    ch["totalLen"] = buffer(2, 2):uint()
    subt = t:add(scion_ch_totallen, buffer(2, 2), ch.totalLen)
    if ch.totalLen ~= pktlen then
        subt:add_tvb_expert_info(scion_ch_totallen_expert, buffer(2, 2),
            string.format("Total length field (%dB) != length of SCION packet (%dB)",
            ch.totalLen, pktlen))
    end
    -- hdr length
    ch["rawHdrLen"] = buffer(4, 1):uint()
    meta["hdrLen"] = ch.rawHdrLen * lineLen
    subt = t:add(scion_ch_hdrlen, buffer(4, 1), meta.hdrLen)
    if meta.hdrLen < chLen + meta.addrTotalLen then
        subt:add_tvb_expert_info(scion_ch_totallen_expert, buffer(4, 1),
            string.format("Header length field (%d=%dB) < length of common + address headers (%dB)",
            ch.rawHdrLen, meta.hdrLen, chLen + meta.addrTotalLen))
    elseif meta.hdrLen > ch.totalLen then
        subt:add_tvb_expert_info(scion_ch_totallen_expert, buffer(4, 1),
            string.format("Header length field (%d=%dB) > total length field (%dB)",
            ch.rawHdrLen, meta.hdrLen, ch.totalLen))
    end
    -- path meta data
    meta["pathOffset"] = chLen + meta.addrTotalLen
    meta["pathLen"] = meta.hdrLen - meta.pathOffset
    -- info offset
    ch["rawInfOff"] = buffer(5, 1):uint()
    meta["infOff"] = ch.rawInfOff * lineLen
    subt = t:add(scion_ch_infoff, buffer(5, 1), meta.infOff)
    if meta.pathLen == 0 and meta.infOff > 0 then
        subt:add_tvb_expert_info(scion_ch_infoff_expert, buffer(5, 1),
            string.format("Non-zero Info Field offset (%d=%dB) with zero-length path",
            ch.rawInfOff, meta.infOff))
    elseif meta.pathLen > 0 and meta.infOff < meta.pathOffset then
        subt:add_tvb_expert_info(scion_ch_infoff_expert, buffer(5, 1),
            string.format("Info Field offset (%d=%dB) too low", ch.rawInfOff, meta.infOff))
    elseif meta.pathLen > 0 and meta.infOff > meta.hdrLen then
        subt:add_tvb_expert_info(scion_ch_infoff_expert, buffer(5, 1),
            string.format("Info Field offset (%d=%dB) too high", ch.rawInfOff, meta.infOff))
    end
    -- hop offset
    ch["rawHopOff"] = buffer(6, 1):uint()
    meta["hopOff"] = ch.rawHopOff * lineLen
    subt = t:add(scion_ch_hopoff, buffer(6, 1), meta.hopOff)
    if meta.pathLen == 0 and meta.hopOff > 0 then
        subt:add_tvb_expert_info(scion_ch_hopoff_expert, buffer(5, 1),
            string.format("Non-zero Hop offset (%d=%dB) with zero-length path",
            ch.rawHopOff, meta.hopOff))
    elseif meta.pathLen > 0 and meta.hopOff < (meta.pathOffset + lineLen) then
        subt:add_tvb_expert_info(scion_ch_hopoff_expert, buffer(5, 1),
            string.format("Hop Field offset (%d=%dB) too low", ch.rawHopOff, meta.hopOff))
    elseif meta.pathLen > 0 and meta.hopOff > meta.hdrLen then
        subt:add_tvb_expert_info(scion_ch_hopoff_expert, buffer(5, 1),
            string.format("Hop Field offset (%d=%dB) too high", ch.rawHopOff, meta.hopOff))
    end
    ch["rawNextHdr"] = buffer(7, 1):uint()
    meta["nextHdr"] = hdrTypes[ch.rawNextHdr]
    t:add(scion_ch_nexthdr, buffer(7, 1), ch.rawNextHdr)
    return ch, meta
end

function parse_addr_hdr(buffer, tree, meta)
    local t = tree:add(buffer, string.format("Address header [%dB]", meta.addrTotalLen))
    -- dst ISD-AS
    local dstIaT = t:add(buffer(0, iaLen), string.format("Destination ISD-AS [%dB]", iaLen))
    meta["dstIsd"] = buffer(0, 2):bitfield(0, 12)
    dstIaT:add(scion_addr_dst_isd, buffer(0, 2), meta.dstIsd)
    meta["dstAs"] = buffer(0, iaLen):bitfield(12, 20)
    dstIaT:add(scion_addr_dst_as, buffer(1, iaLen-1), meta.dstAs)
    -- src ISD-AS
    local srcIaT = t:add(buffer(iaLen, iaLen), string.format("Source ISD-AS [%dB]", iaLen))
    meta["srcIsd"] = buffer(iaLen, 2):bitfield(0, 12)
    srcIaT:add(scion_addr_src_isd, buffer(iaLen, 2), meta.srcIsd)
    meta["srcAs"] = buffer(iaLen, iaLen):bitfield(12, 20)
    srcIaT:add(scion_addr_src_as, buffer(iaLen+1, iaLen-1), meta.srcAs)
    -- dst addr
    local dstBuf = buffer(iaLen * 2, addrLens[meta.dstType])
    if meta.dstType == "IPv4" then
        t:add(scion_addr_dst_ipv4, dstBuf, dstBuf:ipv4())
    elseif meta.dstType == "IPv6" then
        t:add(scion_addr_dst_ipv6, dstBuf, dstBuf:ipv6())
    elseif meta.dstType == "SVC" then
        t:add(scion_addr_dst_svc, dstBuf, dstBuf:uint())
    end
    -- src addr
    local srcBuf = buffer(iaLen * 2 + addrLens[meta.dstType], addrLens[meta.srcType])
    if meta.srcType == "IPv4" then
        t:add(scion_addr_src_ipv4, srcBuf, srcBuf:ipv4())
    elseif meta.srcType == "IPv6" then
        t:add(scion_addr_src_ipv6, srcBuf, srcBuf:ipv6())
    end
    -- padding
    if meta.addrPadding > 0 then
        t:add(scion_addr_padding, buffer(meta.addrLen, meta.addrPadding))
    end
end

function parse_path_hdr(buffer, tree, meta)
    local t = tree:add(buffer, string.format("Path header [%dB]", meta.pathLen))
    local offset = 0
    local segNr = 0
    while offset < meta.pathLen do
        offset = offset + parse_path_seg(buffer(offset), t, segNr)
        segNr = segNr + 1
    end
end

function parse_path_seg(buffer, tree, segNr)
    local hops = buffer(7, 1):uint()
    local segLen = (hops + 1) * lineLen
    local t = tree:add(buffer, string.format("Segment %d [%dB]", segNr, segLen))
    ts = parse_info_field(buffer(0, 8), t)
    for i = 0, hops-1, 1 do
        parse_hop_field(buffer((i+1) * lineLen, lineLen), t, i, ts)
    end
    return segLen
end

function parse_info_field(buffer, tree)
    local t = tree:add(buffer, string.format("Info Field [%dB]", lineLen))
    local flags = buffer(0, 1) 
    flagsT = t:add(scion_path_info_flags, flags, flags:uint(), info_flag_desc(flags:uint()))
    flagsT:add(scion_path_info_flags_peer, flags)
    flagsT:add(scion_path_info_flags_shortcut, flags)
    flagsT:add(scion_path_info_flags_up, flags)
    local ts = buffer(1, 4):uint()
    t:add(scion_path_info_ts, buffer(1, 4))
    t:add(scion_path_info_isd, buffer(5, 2))
    t:add(scion_path_info_hops, buffer(7, 1))
    return ts
end

function info_flag_desc(flag)
    local desc = {}
    if bit.band(flag, 0x1) > 0 then
        table.insert(desc, "UP")
    else
        table.insert(desc, "DOWN")
    end
    if bit.band(flag, 0x2) > 0 then
        if bit.band(flag, 0x4) > 0 then
            table.insert(desc, "SHORTCUT-PEER")
        else
            table.insert(desc, "SHORTCUT")
        end
    end
    return string.format("0x%x [%s]", flag, table.concat(desc, ","))
end

function parse_hop_field(buffer, tree, hopNr, ts)
    local t = tree:add(buffer, string.format("Hop Field %d [%dB]", hopNr, lineLen))
    local flags = buffer(0, 1)
    flagsT = t:add(scion_path_hop_flags, flags, flags:uint(), hop_flag_desc(flags:uint()))
    flagsT:add(scion_path_hop_flags_recurse, flags)
    flagsT:add(scion_path_hop_flags_fwdonly, flags)
    flagsT:add(scion_path_hop_flags_verifyonly, flags)
    flagsT:add(scion_path_hop_flags_xover, flags)
    local rawExpTime = buffer(1, 1):uint()
    local subt = t:add(scion_path_hop_exp_raw, buffer(1, 1), rawExpTime)
    subt:add(scion_path_hop_exp_rel, buffer(1, 1), NSTime.new(rawExpTime * segExpUnit))
    subt:add(scion_path_hop_exp_abs, buffer(1, 1), NSTime.new((rawExpTime * segExpUnit) + ts))
    -- XXX(kormat): this assumes the "standard" hop field size and layout, 2x 12bit IFIDs in 3B.
    t:add(scion_path_hop_ingress_if, buffer(2, 2), buffer(2, 2):uint64():rshift(4))
    t:add(scion_path_hop_egress_if, buffer(3, 2), buffer(3, 2):uint64():band(0x0FFF))
    -- XXX(kormat): this assumes the "standard" hop field mac length (3B).
    t:add(scion_path_hop_mac, buffer(5, 3))
end

function hop_flag_desc(flag)
    local desc = {}
    if bit.band(flag, 0x1) > 0 then
        table.insert(desc, "XOVER")
    end
    if bit.band(flag, 0x2) > 0 then
        table.insert(desc, "VERIFY-ONLY")
    end
    if bit.band(flag, 0x4) > 0 then
        table.insert(desc, "FORWARD-ONLY")
    end
    if bit.band(flag, 0x8) > 0 then
        table.insert(desc, "RECURSE")
    end
    return string.format("0x%x [%s]", flag, table.concat(desc, ","))
end

function calc_padding(len, blkSize)
    local spare = len % blkSize
    if spare ~= 0 then
        return blkSize - spare
    end
    return 0
end

-- SCION packet on UDP/IP overlay.
table_udp = DissectorTable.get("udp.port")
-- intra-AS traffic
for i = 30000, 32000, 1 do
    table_udp:add(i, scion_proto)
end
-- inter-AS BR traffic
for i = 50000, 50050, 1 do
    table_udp:add(i, scion_proto)
end
