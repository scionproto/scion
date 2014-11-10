--define protocol
scion_proto = Proto("scion","SCION","SCION Protocol")

--define protocol fields
scion_ch_version=ProtoField.uint8("scion.ch.version","Version",base.HEX, nil, 0xf0)
scion_ch_srclen=ProtoField.uint16("scion.ch.srclen","Source address length",base.DEC, nil, 0x0fc0)
scion_ch_dstlen=ProtoField.uint8("scion.ch.dstlen","Dstination address length",base.DEC, nil, 0x3f)
scion_ch_totallen=ProtoField.uint8("scion.ch.totallen","Total length",base.DEC)
scion_ch_timestamp=ProtoField.uint8("scion.ch.timestamp","Timestamp",base.DEC)
scion_ch_currof=ProtoField.uint8("scion.ch.currof","Cuurent opaque field",base.DEC)
scion_ch_nexthdr=ProtoField.uint8("scion.ch.nexthdr","Next header",base.DEC)
scion_ch_hdrlen=ProtoField.uint8("scion.ch.hdrlen","Header length",base.DEC)

scion_proto.fields={scion_ch_version, scion_ch_srclen, scion_ch_dstlen,scion_ch_totallen, scion_ch_timestamp, scion_ch_currof, scion_ch_nexthdr, scion_ch_hdrlen}


--TODO: check each variable should be global or local
function scion_proto.dissector(buffer,pinfo,tree)



-- SCION common header and src/dst adress

	--define protocol fields
	--scion_ch=ProtoField.uint8("scion.ch","SCION common header")	

 	-- Common header information
	version=buffer(0,1):uint()
	version=bit.band(version,0xf0)
	
	--check uppath or downpath
	path_direction="Up path"
	if bit.band(version,0x1) == 1 then
		path_direction="Down path"
	end
	
	srclen=buffer(0,2):uint()
	srclen=bit.rshift(srclen,6)
	srclen=bit.band(srclen,0x3F)
	
	dstlen=buffer(1,1):uint()
	dstlen=bit.band(dstlen,0x3F)

	total_len=buffer(2,2):uint()
	timestamp=buffer(4,1):uint()
	curr_of=buffer(5,1):uint()
	next_hdr=buffer(6,1):uint()
	hdr_len=buffer(7,1):uint()



	-- Source address and destination adress
	--debug
	--srclen=4
	--dstlen=4
	
	srcaddr=buffer(8,srclen)
	dstaddr=buffer(8+srclen,dstlen)
	

	--check packet type
	ptype=""
	if srclen > 0 and dstlen > 0 and srclen < hdr_len and dstlen < hdr_len then
		ptype=get_type(srcaddr:uint(),dstaddr:uint())
	end


	-- add tree
	pinfo.cols.protocol = "SCION"
	scion_tree = tree:add(scion_proto,buffer(0, hdr_len),"SCION Protocol")
	local sch_field = ProtoField.string("sch","Common hdeader")
	local sch_tree = scion_tree:add(sch_field,buffer(0,8),"Common header" .. ", Type:" .. ptype .. ", " ..path_direction)
	

	--sch_tree:add_packet_field(scion_ch_version, buffer(0,1),ENC_ASCII)
	sch_tree:add(scion_ch_version, buffer(0,1))

	--sch_tree:add(buffer(0,2),"Src Len: " .. srclen)
	sch_tree:add(scion_ch_srclen,buffer(0,2))
	if srclen==0 then
		sch_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Src Len = 0")
		return
	end
	--sch_tree:add(buffer(1,1),"Dst Len: " .. dstlen)
	sch_tree:add(scion_ch_dstlen,buffer(1,1))
	if dstlen==0 then
		sch_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Dst Len = 0")
		return
	end

	--sch_tree:add(buffer(2,2),"Total Len: " .. total_len)
	--sch_tree:add(buffer(4,1),"Timestamp: " .. timestamp)
	--sch_tree:add(buffer(5,1),"Curr OF: " .. curr_of)
	--sch_tree:add(buffer(6,1),"Next Hdr: " .. next_hdr)   
	--sch_tree:add(buffer(7,1),"Hdr len: " .. hdr_len)
	sch_tree:add_packet_field(scion_ch_totallen,buffer(2,2),ENC_ASCII)
	sch_tree:add_packet_field(scion_ch_timestamp,buffer(4,1),ENC_ASCII)
	sch_tree:add_packet_field(scion_ch_currof,buffer(5,1),ENC_ASCII)
	sch_tree:add_packet_field(scion_ch_nexthdr,buffer(6,1),ENC_ASCII)   
	sch_tree:add_packet_field(scion_ch_hdrlen,buffer(7,1),ENC_ASCII)

	--check buffer length
	if buffer:len() < hdr_len then
		--fragmented?
		scion_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "packet length < hdr_len")
	end
	--check length
	if total_len < hdr_len then
		scion_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "total_len < hdr_len")
	end


	if ptype == "DATA" then
		process_data(buffer,pinfo,tree)
	elseif ptype == "BEACON" then
		process_beacon(buffer,pinfo,tree)
	end
end

function process_data(buffer,pinfo,tree)
	--check src and destination address
	local srcdst_field = ProtoField.string("srcdst","Source/Destination address")
	local srcdst_tree = scion_tree:add(srcdst_field,buffer(8,8),"Source/Destination address")
	srcdst_tree:add(buffer(8,srclen),"Source adress: " .. srcaddr)
	srcdst_tree:add(buffer(8+srclen,dstlen),"Destination adress: " .. dstaddr)

	--analyze opaque field
	process_of(buffer,pinfo,tree)
end

function process_beacon(buffer,pinfo,tree)
	--analyze opaque field
	local of_field = ProtoField.string("of","Opaque field")
	local of_tree = scion_tree:add(of_field,buffer(of_offset,8),"Opaque field ".. i)

	local of_offset=8+srclen+dstlen;

	oftypename="Special OF"
	of_tree:add(buffer(of_offset,1),"Opaque filed type: " .. oftypename .. " (0x" .. string.format("%x",buffer(of_offset,1):uint()) .. ")")
	of_tree:add(buffer(of_offset+1,2),"Timestamp: " .. buffer(of_offset+1,2))
	of_tree:add(buffer(of_offset+3,2),"ISD ID: " .. buffer(of_offset+3,2))
	of_tree:add(buffer(of_offset+5,1),"Hops: " .. buffer(of_offset+5,1))
	of_tree:add(buffer(of_offset+6,2),"Reserved: " .. buffer(of_offset+6,2))

	of_offset=of_offset+8
	oftypename="ROT OF"
	of_tree:add(buffer(of_offset,1),"Opaque filed type: " .. oftypename .. " (0x" .. string.format("%x",buffer(of_offset,1):uint()) .. ")")
	of_tree:add(buffer(of_offset+1,2),"ROT version: " .. buffer(of_offset+1,4))
	of_tree:add(buffer(of_offset+3,2),"ISD ID: " .. buffer(of_offset+5,2))
	of_tree:add(buffer(of_offset+6,2),"Reserved: " .. buffer(of_offset+7,1))



	--PCBMarking
	local pcb_size=32
	local i=0
	local pcb_tree = scion_tree:add(buffer(of_offset,hdr_len - of_offset),"PCB")
	for of_offset=of_offset+8, of_offset + pcb_size < hdr_len, pcb_size do
		local pcbsub_tree = pcb_tree:add(buffer(of_offset,pcb_size),"PCB Marking ".. i)

		pcbtree:add(buffer(of_offset,8),"AD ID: " .. buffer(of_offset,8))

		local ssf_tree=pcbtree:add(buffer(of_offset+8,8),"Support signature field: " .. buffer(of_offset+8,8))
		ssf_tree:add(buffer(of_offset+8,4),"Certificate ID" .. buffer(of_offset+8,4))
		ssf_tree:add(buffer(of_offset+8+4,2),"Signature length" .. buffer(of_offset+8+4,2))
		ssf_tree:add(buffer(of_offset+8+6,2),"Block size" .. buffer(of_offset+8+6,2))

		local hof_tree=pcbtree:add(buffer(of_offset+16,8),"Hop opaque field: " .. buffer(of_offset+16,8))
		hof_tree:add(buffer(of_offset+16+1,2),"Ingress IF: " .. buffer(of_offset+1,2))
		hof_tree:add(buffer(of_offset+16+3,2),"Egress IF: " .. buffer(of_offset+3,2))
		hof_tree:add(buffer(of_offset+16+5,3),"MAC: " .. buffer(of_offset+5,3))
		
		local spf_tree=pcbtree:add(buffer(of_offset+24,8),"Support PCB field: " .. buffer(of_offset+24,8))
		spf_tree:add(buffer(of_offset+24,2),"ISD ID: " .. buffer(of_offset+24,2))
		spf_tree:add(buffer(of_offset+24+2,1),"Bandwidth allocation F: " .. buffer(of_offset+24+2,1))
		spf_tree:add(buffer(of_offset+24+3,1),"Bandwidth allocation R: " .. buffer(of_offset+24+3,1))
		spf_tree:add(buffer(of_offset+24+4,1),"Dynamic bandwidth allocation F: " .. buffer(of_offset+24+4,1))
		spf_tree:add(buffer(of_offset+24+5,1),"Dynamic bandwidth allocation R: " .. buffer(of_offset+24+5,1))
		spf_tree:add(buffer(of_offset+24+6,1),"BE bandwidth F: " .. buffer(of_offset+24+6,1))
		spf_tree:add(buffer(of_offset+24+7,1),"BE bandwidth R: " .. buffer(of_offset+24+7,1))

		i=i+1
	end

end


function process_of(buffer,pinfo,tree)
--Opaque field
--TODO: add ProtoField

	local num_special_op=2
	--[[	
	if ptype=="DATA" then	
		num_special_op=2
	elseif ptype=="BEACON" then
		num_special_op=1
	end
	--]]

	local num_op=0 -- num_op= hops in special opaque field
	--for i=0, num_special_op + num_op -1 , 1 do 
	local i=0
	while i <  num_special_op + num_op do
		local of_offset=8+srclen+dstlen + 8*i

		--check range
		if of_offset + 8 > hdr_len then
			scion_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "cannot read opaque field. Hdr_len is small?")
			return
		end


		local of_field = ProtoField.string("of","Opaque field")
		local of_tree = scion_tree:add(of_field,buffer(of_offset,8),"Opaque field ".. i)
		
		
		--check OF type
		local oftype=buffer(of_offset,1):uint()
		local oftypename="???"



		if oftype == 0x80 then
			oftypename="Special OF"
			of_tree:add(buffer(of_offset,1),"Opaque filed type: " .. oftypename .. " (0x" .. string.format("%x",buffer(of_offset,1):uint()) .. ")")
			of_tree:add(buffer(of_offset+1,2),"Timestamp: " .. buffer(of_offset+1,2))
			of_tree:add(buffer(of_offset+3,2),"ISD ID: " .. buffer(of_offset+3,2))
			of_tree:add(buffer(of_offset+5,1),"Hops: " .. buffer(of_offset+5,1))
			of_tree:add(buffer(of_offset+6,2),"Reserved: " .. buffer(of_offset+6,2))
			
			num_op = num_op + buffer(of_offset+5,1):uint() -- plus hops

		elseif oftype == 0xff then
			oftypename="ROT OF"
			of_tree:add(buffer(of_offset,1),"Opaque filed type: " .. oftypename .. " (0x" .. string.format("%x",buffer(of_offset,1):uint()) .. ")")
			of_tree:add(buffer(of_offset+1,2),"ROT version: " .. buffer(of_offset+1,4))
			of_tree:add(buffer(of_offset+3,2),"ISD ID: " .. buffer(of_offset+5,2))
			of_tree:add(buffer(of_offset+6,2),"Reserved: " .. buffer(of_offset+7,1))
		else
			if oftype==0x0 then
				oftypename="Normal OF"
			-- elseif oftype == 0x80 then
			elseif oftype == 0x20 then
				oftypename="TDC XOVR"
			elseif oftype == 0xc0 then
				oftypename="NON TDC XOVR"
			elseif oftype == 0xe0 then
				oftypename="INPATH XOVR"
			elseif oftype == 0xf0 then
				oftypename="TNTRATD PEER"
			elseif oftype == 0xf8 then
				oftypename="INTERTD PEER"
			elseif oftype == 0x10 then
				oftypename="PEER XOVR"

			end
			
			of_tree:add(buffer(of_offset,1),"Opaque filed type: " .. oftypename .. " (0x" .. string.format("%x",buffer(of_offset,1):uint()) .. ")")
			of_tree:add(buffer(of_offset+1,2),"Ingress IF: " .. buffer(of_offset+1,2))
			of_tree:add(buffer(of_offset+3,2),"Egress IF: " .. buffer(of_offset+3,2))
			of_tree:add(buffer(of_offset+5,3),"MAC: " .. buffer(of_offset+5,3))

		end
			
	i = i + 1

	end


-- Payload
-- TODO: check L4 protocol and call a dissector of the protocol
	local data_offset=hdr_len
	local data_size=total_len - hdr_len
	
	payload_dissector=Dissector.get("data")
	payload_dissector:call(buffer(data_offset,data_size):tvb(),pinfo,tree)

end


function get_type(src_addr, dst_addr)

--[[ 
from python code
TYPES_SRC = {
		PacketType.BEACON: 16834570,
		PacketType.CERT_REP: 33611786,
		PacketType.PATH_REP_LOCAL: 50389002,
		PacketType.PATH_REP: 67166218,
		PacketType.PATH_REP_TDC: 83943434,
		PacketType.ROT_REP_LOCAL:100720650,
		PacketType.OFG_KEY_REP: 117497866,
		PacketType.ROT_REP: 134275082,
		PacketType.CERT_REP_LOCAL:151052298,
		PacketType.IFID_REP: 167829514,
		PacketType.UP_PATH: 33612000,
		}
TYPES_SRC_INV = {v: k for k, v in TYPES_SRC.items()}
TYPES_DST = {
		PacketType.CERT_REQ: 33611786,
		PacketType.PATH_REQ_LOCAL:50389002,
		PacketType.PATH_REQ: 67166218,
		PacketType.PATH_REQ_TDC: 83943434,
		PacketType.ROT_REQ_LOCAL: 100720650,
		PacketType.OFG_KEY_REQ: 117497866,
		PacketType.ROT_REQ: 134275082,
		PacketType.CERT_REQ_LOCAL: 151052298,
		PacketType.UP_PATH: 33612000,
		PacketType.PATH_REG: 50389216,
		PacketType.IFID_REQ: 167829514,
	}
--]]
	if src_addr==16834570 then
		return "BEACON"
	elseif src_addr==33611786 then
		return "CERT_REP"
	elseif src_addr==50389002 then
		return "PATH_REP_LOCAL"
	elseif src_addr==67166218 then
		return "PATH_REP"
	elseif src_addr==83943434 then
		return "PATH_REP_TDC"
	elseif src_addr==100720650 then
		return "ROT_REP_LOCAL"
	elseif src_addr==117497866 then
		return "OFG_KEY_REP"
	elseif src_addr==134275082 then
		return "ROT_REP"
	elseif src_addr==151052298 then
		return "CERT_REP_LOCAL"
	elseif src_addr==167829514 then
		return "IFID_REP"
	elseif src_addr==33612000 then
		return "UP_PATH"
	end
	
	if dst_addr==33611786 then
		return "CERT_REQ"
	elseif dst_addr==50389002 then
		return "PATH_REQ_LOCAL"
	elseif dst_addr==67166218 then
		return "PATH_REQ"
	elseif dst_addr==83943434 then
		return "PATH_REQ_TDC"
	elseif dst_addr==100720650 then
		return "ROT_REQ_LOCAL"
	elseif dst_addr==117497866 then
		return "OFG_KEY_REQ"
	elseif dst_addr==134275082 then
		return "ROT_REQ"
	elseif dst_addr==151052298 then
		return "CERT_REQ_LOCAL"
	elseif dst_addr==33612000 then
		return "UP_PATH"
	elseif dst_addr==50389216 then
		return "PATH_REG"
	elseif dst_addr==167829514 then
		return "IFID_REQ"
	end
	
	return "DATA"
end

-- hook SCION packet
-- SCION packet on ethernet
ether_table=DissectorTable.get("ethertype")
ether_table:add(0x3333,scion_proto)

--SCION packet on IP
-- hook proto=40
table_ip =DissectorTable.get("ip.proto")
table_ip:add(40,scion_proto)

--SCION packet on UDP
--assume UDP 33300-33399 are for SCION
table_udp=DissectorTable.get("udp.port")
for i=33300,33399, 1 do
	table_udp:add(i,scion_proto)
end
