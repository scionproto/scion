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
local l4Types = {
    [1] = "SCMP",
    [6] = "TCP",
    [17] = "UDP",
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
local hbhTypes = {
    [0] = "SCMP",
    [1] = "OneHopPath",
    [2] = "SIBRA",
}
local e2eTypes = {
    [0] = "PathTrans",
    [1] = "PathProbe",
    [2] = "SPSE",
}
local scmpClasses = {
    [0] = "GENERAL",
    [1] = "ROUTING",
    [2] = "CMNHDR",
    [3] = "PATH",
    [4] = "EXT",
    [5] = "SIBRA",
}
local scmpTypes = {
    ["GENERAL"] = {
        [0] = "UNSPECIFIED",
        [1] = "ECHO_REQUEST",
        [2] = "ECHO_REPLY",
        [3] = "TRACE_ROUTE_REQUEST",
        [4] = "TRACE_ROUTE_REPLY",
        [5] = "RECORD_PATH_REQUEST",
        [6] = "RECORD_PATH_REPLY",
    },
    ["ROUTING"] = {
        [0] = "UNREACH_NET",
        [1] = "UNREACH_HOST",
        [2] = "L2_ERROR",
        [3] = "UNREACH_PROTO",
        [4] = "UNREACH_PORT",
        [5] = "UNKNOWN_HOST",
        [6] = "BAD_HOST",
        [7] = "OVERSIZE_PKT",
        [8] = "ADMIN_DENIED",
    },
    ["CMNHDR"] = {
        [0] = "BAD_VERSION",
        [1] = "BAD_DST_TYPE",
        [2] = "BAD_SRC_TYPE",
        [3] = "BAD_PKT_LEN",
        [4] = "BAD_IOF_OFFSET",
        [5] = "BAD_HOF_OFFSET",
    },
    ["PATH"] = {
        [0] = "PATH_REQUIRED",
        [1] = "BAD_MAC",
        [2] = "EXPORED_HOPF",
        [3] = "BAD_IF",
        [4] = "REVOKED_IF",
        [5] = "NON_ROUTING_HOPF",
        [6] = "DELIVERY_NON_LOCAL",
        [7] = "BAD_SEGMENT",
        [8] = "BAD_INFO_FIELD",
        [9] = "BAD_HOP_FIELD",
    },
    ["EXT"] = {
        [0] = "TOO_MANY_HOPBYHOP",
        [1] = "BAD_EXT_ORDER",
        [2] = "BAD_HOPBYHOP",
        [3] = "BAD_END2END",
    },
    ["SIBRA"] = {
        [0] = "BAD_VERSION",
        [1] = "SETUP_NO_REQ",
    },
}
local chLen = 8
local lineLen = 8
local iaLen = 8
local maxSegTTL = 12 * 60 * 60
local segExpUnit = maxSegTTL / 2^8
local us_in_s = UInt64.new(1e6)

local scion_packet = ProtoField.bytes("scion.packet", "Raw SCION packet")

local scion_ch_version = ProtoField.uint8("scion.ch.version", "Version", base.HEX)
local scion_ch_dsttype = ProtoField.uint8("scion.ch.dst_type", "Destination address type", base.HEX, addrTypes)
local scion_ch_srctype = ProtoField.uint8("scion.ch.src_type", "Source address type", base.HEX, addrTypes)
local scion_ch_totallen = ProtoField.uint16("scion.ch.total_len", "Total length", base.DEC)
local scion_ch_hdrlen = ProtoField.uint8("scion.ch.hdr_len", "Header length", base.DEC)
local scion_ch_infoff = ProtoField.uint8("scion.ch.inf_off", "Info Field offset", base.DEC)
local scion_ch_hopoff = ProtoField.uint8("scion.ch.hop_off", "Hop Field offset", base.DEC)
local scion_ch_nexthdr = ProtoField.uint8("scion.ch.next_hdr", "Next header", base.DEC, hdrTypes)

local scion_addr_dst_isd = ProtoField.uint16("scion.addr.dst_isd", "Dest ISD", base.DEC)
local scion_addr_dst_as = ProtoField.string("scion.addr.dst_as", "Dest AS")
local scion_addr_src_isd = ProtoField.uint16("scion.addr.src_isd", "Src ISD", base.DEC)
local scion_addr_src_as = ProtoField.string("scion.addr.src_as", "Src AS")
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
local scion_path_info_flags_cons_dir = ProtoField.bool("scion.path.info.flags.cons_dir",
    "ConsDir", 8, nil, 0x1)
-- XXX(kormat): This *should* be base.UTC, but that seems to be bugged in ubuntu 16.04's
-- version of wireshark. Amazingly, using the raw enum value works.
-- https://github.com/wireshark/wireshark/blob/2832f4e97d77324b4e46aac40dae0ce898ae559d/epan/time_fmt.h#L44
local scion_path_info_ts = ProtoField.absolute_time("scion.path.info.ts", "Timestamp", 1001)
local scion_path_info_isd = ProtoField.uint16("scion.path.info.isd", "ISD", base.DEC)
local scion_path_info_hops = ProtoField.uint8("scion.path.info.hops", "Hops", base.DEC)

local scion_path_hop_flags = ProtoField.uint8("scion.path.hop.flags", "Flags", base.HEX)
local scion_path_hop_flags_recurse = ProtoField.bool("scion.path.hop.flags.recurse",
    "Recurse", 8, nil, 0x4)
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
local scion_path_hop_mac = ProtoField.bytes("scion.path.hop.mac", "MAC")

local scion_hdr_type_hbh = ProtoField.uint8("scion.hdr.type.hbh", "Type", nil, hbhTypes)
local scion_hdr_type_e2e = ProtoField.uint8("scion.hdr.type.e2e", "Type", nil, e2eTypes)
local scion_hdr_type_l4 = ProtoField.uint8("scion.hdr.type.l4", "L4 protocol", nil, l4Types)
local scion_hdr_len = ProtoField.uint8("scion.hdr.len", "Header length", base.DEC)
local scion_hdr_ext_type = ProtoField.uint8("scion.hdr.ext_type", "Extension type", base.DEC_HEX)

local scion_extn_scmp_flags = ProtoField.uint8("scion.extn.scmp.flags", "Flags", base.HEX)
local scion_extn_scmp_flags_hbh = ProtoField.bool("scion.extn.scmp.flags.hbh", "HopByHop", 8, nil, 0x2)
local scion_extn_scmp_flags_err = ProtoField.bool("scion.extn.scmp.flags.err", "Error", 8, nil, 0x1)

local scion_scmp_cls = ProtoField.uint16("scion.scmp.class", "Class", base.HEX)
local scion_scmp_type = ProtoField.uint16("scion.scmp.type", "Type", base.HEX)
local scion_scmp_len = ProtoField.uint16("scion.scmp.length", "Length", base.DEC)
local scion_scmp_checksum = ProtoField.bytes("scion.scmp.checksum", "Checksum")
-- XXX(kormat): see the explanation for scion.path.info.ts above for the 1001 magic number.
local scion_scmp_ts = ProtoField.absolute_time("scion.scmp.ts", "Timestamp", 1001)

local scion_udp_srcport = ProtoField.uint16("scion.udp.srcport", "Source Port", base.DEC)
local scion_udp_dstport = ProtoField.uint16("scion.udp.dstport", "Destination Port", base.DEC)
local scion_udp_length = ProtoField.uint16("scion.udp.length", "Length", base.DEC)
local scion_udp_checksum = ProtoField.bytes("scion.udp.checksum", "Checksum")

local scion_l4_pld = ProtoField.bytes("scion.l4.pld", "Payload")
local scion_l4_pld_len = ProtoField.uint16("scion.l4.pld.len", "Length")

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
local scion_l4_type_expert = ProtoExpert.new("scion.l4.type.expert",
    "Unsupported L4 protocol", expert.group.MALFORMED, expert.severity.ERROR)
local scion_scmp_cls_expert = ProtoExpert.new("scion.scmp.class.expert",
    "Unsupported SCMP class", expert.group.MALFORMED, expert.severity.ERROR)
local scion_scmp_type_expert = ProtoExpert.new("scion.scmp.type.expert",
    "Unsupported SCMP type", expert.group.MALFORMED, expert.severity.ERROR)
local scion_scmp_len_expert = ProtoExpert.new("scion.scmp.length.expert",
    "", expert.group.MALFORMED, expert.severity.ERROR)
local scion_udp_len_expert = ProtoExpert.new("scion.udp.length.expert",
    "", expert.group.MALFORMED, expert.severity.ERROR)


scion_proto.fields={
    scion_packet,
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
    scion_path_info_flags_cons_dir,
    scion_path_info_ts,
    scion_path_info_isd,
    scion_path_info_hops,
    scion_path_hop_flags,
    scion_path_hop_flags_recurse,
    scion_path_hop_flags_verifyonly,
    scion_path_hop_flags_xover,
    scion_path_hop_exp_raw,
    scion_path_hop_exp_rel,
    scion_path_hop_exp_abs,
    scion_path_hop_ingress_if,
    scion_path_hop_egress_if,
    scion_path_hop_mac,
    scion_hdr_type_hbh,
    scion_hdr_type_e2e,
    scion_hdr_type_l4,
    scion_hdr_len,
    scion_hdr_ext_type,
    scion_extn_scmp_flags,
    scion_extn_scmp_flags_hbh,
    scion_extn_scmp_flags_err,
    scion_scmp_cls,
    scion_scmp_type,
    scion_scmp_len,
    scion_scmp_checksum,
    scion_scmp_ts,
    scion_udp_srcport,
    scion_udp_dstport,
    scion_udp_length,
    scion_udp_checksum,
    scion_l4_pld,
    scion_l4_pld_len,
}

scion_proto.experts = {
    scion_ch_ver_expert,
    scion_ch_addrtype_expert,
    scion_ch_totallen_expert,
    scion_ch_hdrlen_expert,
    scion_ch_infoff_expert,
    scion_ch_hopoff_expert,
    scion_l4_type_expert,
    scion_scmp_cls_expert,
    scion_scmp_type_expert,
    scion_scmp_len_expert,
    scion_udp_len_expert,
}


function scion_proto.dissector(buffer, pinfo, tree)
    tree:add(scion_packet, buffer())
    local meta = {["pkt"] = buffer, ["protocol"] = "SCION"}  -- Metadata about the packet
    local ch = parse_cmn_hdr(buffer(0, chLen), tree, meta)
    if ch == nil or meta == nil then
        return
    end
    parse_addr_hdr(buffer(chLen, meta.addrTotalLen), tree, meta)
    if meta.pathLen > 0 then
        parse_path_hdr(buffer(meta.pathOffset, meta.pathLen), tree, meta)
    end
    if ch.totalLen == meta.hdrLen then
        -- There's no extensions or l4 header.
        return
    end
    parse_ext_hdrs(buffer(meta.hdrLen), tree, ch, meta)
    if meta.rawL4Type == nil then
        -- There's no l4 header
        return
    end
    parse_l4_hdr(buffer(meta.l4Offset), tree, meta)
    pinfo.cols.protocol:set(meta.protocol)
    pinfo.cols.info:append(string.format(", %s -> %s", meta.srcStr, meta.dstStr))
    if meta.pldOffset ~= nil then
        local subt = tree:add(buffer(meta.pldOffset),
            string.format("Payload [%dB]", buffer(meta.pldOffset):len()))
        subt:add(scion_l4_pld, buffer(meta.pldOffset))
        subt:add(scion_l4_pld_len, buffer(meta.pldOffset):len())
    end
end

function parse_cmn_hdr(buffer, tree, meta)
    local ch = {}  -- Direct representation of Common Header
    local t = tree:add(buffer, "SCION Common header [8B]")
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
    if ch.totalLen ~= meta.pkt:len() then
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
    meta["nextHdrTVB"] = buffer(7, 1)
    t:add(scion_ch_nexthdr, buffer(7, 1), ch.rawNextHdr)
    return ch
end

function format_as(as)
    local asDec = as:uint64()
    if asDec > 1 and asDec <= 0xffffffff then
        asStr = string.format("%d", asDec)
    else
        asStr = string.format("%x:%x:%x", as:bitfield(0, 16), as:bitfield(16, 16), as:bitfield(32, 16))
    end
    return asStr
end

function parse_addr_hdr(buffer, tree, meta)
    local t = tree:add(buffer, string.format("SCION Address header [%dB]", meta.addrTotalLen))
    -- dst ISD-AS
    local dstIaT = t:add(buffer(0, iaLen), string.format("Destination ISD-AS [%dB]", iaLen))
    meta["dstIsd"] = buffer(0, 2):bitfield(0, 16)
    dstIaT:add(scion_addr_dst_isd, buffer(0, 2), meta.dstIsd)
    local dstAs = buffer(2, iaLen - 2)
    meta["dstAs"] = format_as(dstAs)
    dstIaT:add(scion_addr_dst_as, dstAs, meta.dstAs)
    -- src ISD-AS
    local srcIaT = t:add(buffer(iaLen, iaLen), string.format("Source ISD-AS [%dB]", iaLen))
    meta["srcIsd"] = buffer(iaLen, 2):bitfield(0, 16)
    srcIaT:add(scion_addr_src_isd, buffer(iaLen, 2), meta.srcIsd)
    local srcAs = buffer(iaLen + 2, iaLen - 2)
    meta["srcAs"] = format_as(srcAs)
    srcIaT:add(scion_addr_src_as, srcAs, meta.srcAs)
    -- dst addr
    local dstBuf = buffer(iaLen * 2, addrLens[meta.dstType])
    local dstProto, dstAddr
    if meta.dstType == "IPv4" then
        dstProto = scion_addr_dst_ipv4
        dstAddr = dstBuf:ipv4()
    elseif meta.dstType == "IPv6" then
        dstProto = scion_addr_dst_ipv6
        dstAddr = dstBuf:ipv6()
    elseif meta.dstType == "SVC" then
        dstProto = scion_addr_dst_svc
        dstAddr = dstBuf:uint()
    end
    t:add(dstProto, dstBuf, dstAddr)
    -- src addr
    local srcBuf = buffer(iaLen * 2 + addrLens[meta.dstType], addrLens[meta.srcType])
    local srcProto, srcAddr
    if meta.srcType == "IPv4" then
        srcProto = scion_addr_src_ipv4
        srcAddr = srcBuf:ipv4()
    elseif meta.srcType == "IPv6" then
        srcProto = scion_addr_src_ipv6
        srcAddr = srcBuf:ipv6()
    end
    t:add(srcProto, srcBuf, srcAddr)
    -- padding
    if meta.addrPadding > 0 then
        t:add(scion_addr_padding, buffer(meta.addrLen, meta.addrPadding))
    end
    meta["srcStr"] = string.format("%d-%s,[%s]", meta.srcIsd, meta.srcAs, srcAddr)
    meta["dstStr"] = string.format("%d-%s,[%s]", meta.dstIsd, meta.dstAs, dstAddr)
    t:append_text(string.format(", %s -> %s", meta.srcStr, meta.dstStr))
end

function parse_path_hdr(buffer, tree, meta)
    local t = tree:add(buffer, string.format("SCION Path header [%dB]", meta.pathLen))
    local offset = 0
    local segNr = 0
    while offset < meta.pathLen do
        offset = offset + parse_path_seg(buffer(offset), t, segNr)
        segNr = segNr + 1
    end
    t:append_text(string.format(", %d Segment(s), %d Hop fields",
        segNr, (offset - (segNr * lineLen)) / lineLen))
end

function parse_path_seg(buffer, tree, segNr)
    local hops = buffer(7, 1):uint()
    local segLen = (hops + 1) * lineLen
    local t = tree:add(buffer, string.format("Segment %d [%dB]", segNr, segLen))
    ts = parse_info_field(buffer(0, 8), t)
    for i = 0, hops-1, 1 do
        parse_hop_field(buffer((i+1) * lineLen, lineLen), t, i, ts)
    end
    local t = tree:add(buffer, string.format("Segment %d [%dB], %d Hop field(s)", segNr, segLen, hops))
    return segLen
end

function parse_info_field(buffer, tree)
    local t = tree:add(buffer, string.format("Info Field [%dB]", lineLen))
    local flags = buffer(0, 1) 
    local flagsT = t:add(scion_path_info_flags, flags)
    flagsT:append_text(", " .. info_flag_desc(flags:uint()))
    flagsT:add(scion_path_info_flags_peer, flags)
    flagsT:add(scion_path_info_flags_shortcut, flags)
    flagsT:add(scion_path_info_flags_cons_dir, flags)
    local ts = buffer(1, 4):uint()
    t:add(scion_path_info_ts, buffer(1, 4))
    t:add(scion_path_info_isd, buffer(5, 2))
    t:add(scion_path_info_hops, buffer(7, 1))
    tree:append_text(string.format(", ISD: %s, Len: %d %s", buffer(5, 2):uint(), buffer(7, 1):uint(),
        info_flag_desc(flags:uint())))
    return ts
end

function info_flag_desc(flag)
    local desc = {}
    if bit.band(flag, 0x1) > 0 then
        table.insert(desc, "CONS_DIR")
    else
        table.insert(desc, "NOT_CONS_DIR")
    end
    if bit.band(flag, 0x2) > 0 then
        if bit.band(flag, 0x4) > 0 then
            table.insert(desc, "SHORTCUT-PEER")
        else
            table.insert(desc, "SHORTCUT")
        end
    end
    return string.format("[%s]", table.concat(desc, ","))
end

function parse_hop_field(buffer, tree, hopNr, ts)
    local t = tree:add(buffer, string.format("Hop Field %d [%dB]", hopNr, lineLen))
    local flags = buffer(0, 1)
    local flagsT = t:add(scion_path_hop_flags, flags)
    flagsT:append_text(", " .. hop_flag_desc(flags:uint()))
    flagsT:add(scion_path_hop_flags_recurse, flags)
    flagsT:add(scion_path_hop_flags_verifyonly, flags)
    flagsT:add(scion_path_hop_flags_xover, flags)
    local rawExpTime = buffer(1, 1):uint()
    local subt = t:add(scion_path_hop_exp_raw, buffer(1, 1), rawExpTime)
    subt:add(scion_path_hop_exp_rel, buffer(1, 1), NSTime.new(rawExpTime * segExpUnit))
    subt:add(scion_path_hop_exp_abs, buffer(1, 1), NSTime.new((rawExpTime * segExpUnit) + ts))
    -- XXX(kormat): this assumes the "standard" hop field size and layout, 2x 12bit IFIDs in 3B.
    local igIF = buffer(2, 2):uint64():rshift(4)
    local egIF = buffer(3, 2):uint64():band(0x0FFF)
    t:add(scion_path_hop_ingress_if, buffer(2, 2), igIF)
    t:add(scion_path_hop_egress_if, buffer(3, 2), egIF)
    -- XXX(kormat): this assumes the "standard" hop field mac length (3B).
    t:add(scion_path_hop_mac, buffer(5, 3))
    t:append_text(string.format(", Ig: #%s, Eg: #%s, %s", igIF, egIF, hop_flag_desc(flags:uint())))
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
        table.insert(desc, "RECURSE")
    end
    if #desc == 0 then
        return ""
    end
    return string.format("[%s]", table.concat(desc, ","))
end

function parse_ext_hdrs(buffer, tree, ch, meta)
    local rawNextHdr = ch.rawNextHdr
    local offset = 0
    if (rawNextHdr == 0 and meta.hdrLen < ch.totalLen) then
        local t = tree:add("SCION Hop-By-Hop (HBH) Extensions")
        while meta.hdrLen + offset < ch.totalLen do
            if rawNextHdr ~= 0 then
                -- Reached a non-e2e header
                break
            end
            hdrLen, rawNextHdr = parse_hbh_ext(buffer(offset), t, meta)
            offset = offset + hdrLen
        end
    end
    if rawNextHdr == 222 then
        local t = tree:add("SCION End-To-End (E2E) Extensions")
        while meta.hdrLen + offset < ch.totalLen do
            if rawNextHdr ~= 222 then
                -- Reached a non-hbh header.
                break
            end
            hdrLen, rawNextHdr = parse_e2e_ext(buffer(offset), t, meta)
            offset = offset + hdrLen
        end
    end
    if meta.hdrLen + offset < ch.totalLen then
        meta["rawL4Type"] = rawNextHdr
        meta["l4Type"] = l4Types[rawNextHdr]
        meta["l4Offset"] = meta.hdrLen + offset
    end
end

function parse_hbh_ext(buffer, tree, meta)
    local extLen = buffer(1, 1):uint() * lineLen
    local extType = buffer(2, 1):uint()
    local t = tree:add(buffer(0, extLen), string.format("%s [%dB]", hbhTypes[extType], extLen))
    t:add(scion_hdr_type_hbh, buffer(2, 1))
    t:add(scion_hdr_len, buffer(1, 1), extLen)
    if hbhTypes[extType] == "SCMP" then
        parse_hbh_scmp(buffer(3, extLen - 3), t)
    end
    meta.nextHdrTVB = buffer(0, 1)
    return extLen, buffer(0, 1):uint()
end

function parse_hbh_scmp(buffer, tree)
    local flags = buffer(0, 1)
    local flagsT = tree:add(scion_extn_scmp_flags, flags)
    tree:append_text(", " .. hbh_scmp_flag_desc(flags:uint()))
    flagsT:append_text(", " .. hbh_scmp_flag_desc(flags:uint()))
    flagsT:add(scion_extn_scmp_flags_hbh, flags)
    flagsT:add(scion_extn_scmp_flags_err, flags)
end

function hbh_scmp_flag_desc(flag)
    local desc = {}
    if bit.band(flag, 0x1) > 0 then
        table.insert(desc, "ERROR")
    end
    if bit.band(flag, 0x2) > 0 then
        table.insert(desc, "HBH")
    end
    return string.format("[%s]", table.concat(desc, ","))
end

function parse_e2e_ext(buffer, tree, meta)
    local extLen = buffer(1, 1):uint() * lineLen
    local extType = buffer(2, 1):uint()
    local t = tree:add(buffer(0, extLen), string.format("E2E Ext: %s [%dB]",
        e2eTypes[extType], extLen))
    t:add(scion_hdr_type_e2e, buffer(2, 1))
    t:add(scion_hdr_len, buffer(1, 1), extLen)
    meta.nextHdrTVB = buffer(0, 1)
    return extLen, buffer(0, 1):uint()
end

function parse_l4_hdr(buffer, tree, meta)
    -- Add a l4 header type entry separately to the actual L4 header entry,
    -- so that it can be associated with the source of the "next header" type.
    local t = tree:add(scion_hdr_type_l4, meta.nextHdrTVB, meta.rawL4Type)
    if meta.l4Type == nil then
        t:add_tvb_expert_info(scion_l4_type_expert, meta.nextHdrTVB)
    elseif meta.l4Type == "SCMP" then
        parse_scmp_hdr(buffer, tree, meta)
        meta.protocol = "SCMP/SCION"
    elseif meta.l4Type == "UDP" then
        parse_udp_hdr(buffer, tree, meta)
        meta.protocol = "UDP/SCION"
    else
        meta.protocol = "?/SCION"
    end
end

function parse_scmp_hdr(buffer, tree, meta)
    local t = tree:add(buffer(0, 8), "SCMP/SCION [16B]")
    local subt = t:add(scion_scmp_cls, buffer(0, 2))
    local clsStr = scmpClasses[buffer(0, 2):uint()]
    if clsStr == nil then
        clsStr = "UNKNOWN"
    end
    t:append_text(", " .. clsStr)
    subt:append_text(string.format(" (%s)", clsStr))
    subt = t:add(scion_scmp_type, buffer(2, 2))
    if clsStr ~= "UNKNOWN" then
        local typeStr = scmpTypes[clsStr][buffer(2, 2):uint()]
        t:append_text(":" .. typeStr)
        subt:append_text(string.format(" (%s)", typeStr))
    end
    local scmpLen = buffer(4, 2):uint()
    subt = t:add(scion_scmp_len, buffer(4, 2))
    if scmpLen ~= buffer():len() then
        subt:add_tvb_expert_info(scion_scmp_len_expert, buffer(4, 2),
            string.format("SCMP length field (%dB) != L4 length (%dB)",
            scmpLen, buffer():len()))
    end
    -- TODO(kormat): add checksum validation (this will be a lot of work).
    t:add(scion_scmp_checksum, buffer(6, 2))
    local ts = buffer(8, 8):uint64()
    local ts_s = ts / us_in_s
    local ts_us = ts % us_in_s
    t:add(scion_scmp_ts, buffer(8, 8), NSTime.new(ts_s:tonumber(), ts_us:tonumber() * 1000))
end

function parse_udp_hdr(buffer, tree, meta)
    local t = tree:add(buffer(0, 8), "UDP/SCION [8B]")
    t:add(scion_udp_srcport, buffer(0, 2))
    t:add(scion_udp_dstport, buffer(2, 2))
    local udpLen = buffer(4, 2):uint()
    local subt = t:add(scion_udp_length, buffer(4, 2))
    if udpLen ~= buffer():len() then
        subt:add_tvb_expert_info(scion_udp_len_expert, buffer(4, 2),
            string.format("UDP length field (%dB) != L4 length (%dB)",
            udpLen, buffer():len()))
    end
    t:add(scion_udp_checksum, buffer(6, 2))
    -- TODO(kormat): add checksum validation (this will be a lot of work).
    meta["pldOffset"] = meta.l4Offset + 8
    local srcPort = buffer(0, 2):uint()
    local dstPort = buffer(2, 2):uint()
    t:append_text(string.format(", %d -> %d", srcPort, dstPort))
    meta.srcStr = meta.srcStr .. ":" .. srcPort
    meta.dstStr = meta.dstStr .. ":" .. dstPort
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
