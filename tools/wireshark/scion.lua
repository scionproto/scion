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
