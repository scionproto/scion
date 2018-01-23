--define protocol
scion_proto = Proto("scion","SCION","SCION Protocol")

--define protocol fields
scion_ch_version=ProtoField.uint8("scion.ch.version","Version",base.HEX, nil, 0xf0)
scion_ch_srclen=ProtoField.uint16("scion.ch.srclen","Source address length",base.DEC, nil, 0x0fc0)
scion_ch_dstlen=ProtoField.uint8("scion.ch.dstlen","Destination address length",base.DEC, nil, 0x3f)
scion_ch_totallen=ProtoField.uint8("scion.ch.totallen","Total length",base.DEC)
scion_ch_timestamp=ProtoField.uint8("scion.ch.timestamp","Timestamp",base.DEC)
scion_ch_currof=ProtoField.uint8("scion.ch.currof","Current opaque field",base.DEC)
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
	ISD_AD_LEN=4  -- ISD ID 12 bits, AD ID 20 bits
	CMN_HDR_LEN=8 -- common header length
	OPAQUEFIELD_LEN=8
	IPV4_ADDR_LEN=4
	IPV6_ADDR_LEN=16

	srcaddr=buffer(CMN_HDR_LEN,srclen)
	srcaddr_host=buffer(CMN_HDR_LEN+ISD_AD_LEN,srclen-ISD_AD_LEN)
	dstaddr=buffer(CMN_HDR_LEN+srclen,dstlen)
	dstaddr_host=buffer(CMN_HDR_LEN+srclen+ISD_AD_LEN,dstlen-ISD_AD_LEN)
	

	--check packet type
	ptype=""
	if srclen > 0 and dstlen > 0 and srclen < hdr_len and dstlen < hdr_len then
		ptype=get_type(srcaddr_host:le_uint(),dstaddr_host:le_uint())
	end


	-- add tree
	pinfo.cols.protocol = "SCION"
	scion_tree = tree:add(scion_proto,buffer(0, hdr_len),"SCION Protocol")
	local sch_field = ProtoField.string("sch","Common header")
	local sch_tree = scion_tree:add(sch_field,buffer(0,CMN_HDR_LEN),"Common header" .. ", Type:" .. ptype .. ", " ..path_direction)
	

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

	scion_tree:add_expert_info(PI_DEBUG,PI_CHAT,"dummy")

end

function process_data(buffer,pinfo,tree)
	--check src and destination address
	local srcdst_field = ProtoField.string("srcdst","Source/Destination address")
	local srcdst_tree = scion_tree:add(srcdst_field,buffer(CMN_HDR_LEN,srclen+dstlen),"Source/Destination address")

	local srcaddr=buffer(CMN_HDR_LEN,srclen)
	local src_isd_id=bit.rshift(buffer(CMN_HDR_LEN,4):uint(),20)  --first 12 bits are ISD ID
	local src_ad_id=bit.band(buffer(CMN_HDR_LEN,4):uint(),0x000fffff) -- 20 bits are AD ID

	local srcaddr_host=buffer(CMN_HDR_LEN+ISD_AD_LEN,srclen-ISD_AD_LEN):uint()
	local srcaddr_host_text=""
	if srclen-ISD_AD_LEN == IPV4_ADDR_LEN then 
		srcaddr_host_text= buffer(CMN_HDR_LEN+ISD_AD_LEN+1,1):uint() .. "." .. buffer(CMN_HDR_LEN+ISD_AD_LEN+1,1):uint() .. "." .. buffer(CMN_HDR_LEN+ISD_AD_LEN+2,1):uint() .. "." .. buffer(CMN_HDR_LEN+ISD_AD_LEN+3,1):uint()
	else
		-- TODO show IPv6 address
	end

	local dstaddr=buffer(CMN_HDR_LEN+srclen,dstlen)
	local dst_isd_id=bit.rshift(buffer(CMN_HDR_LEN+srclen,4):uint(),20) --first 12 bits are ISD ID
	local dst_ad_id=bit.band(buffer(CMN_HDR_LEN+srclen,4):uint(),0x000fffff)
	local dstaddr_host=buffer(CMN_HDR_LEN+srclen+ISD_AD_LEN,dstlen-ISD_AD_LEN):uint()
	local dstaddr_host_text=""
	if dstlen-ISD_AD_LEN == IPV4_ADDR_LEN then 
		dstaddr_host_text= buffer(CMN_HDR_LEN+srclen+ISD_AD_LEN,1):uint() .. "." .. buffer(CMN_HDR_LEN+srclen+ISD_AD_LEN+1,1):uint() .. "." .. buffer(CMN_HDR_LEN+srclen+ISD_AD_LEN+2,1):uint() .. "." .. buffer(CMN_HDR_LEN+srclen+ISD_AD_LEN+3,1):uint()
	else
		-- TODO show IPv6 address
	end
	
	--srcdst_tree:add(buffer(8,srclen),"Source adress: " .. srcaddr)
	--srcdst_tree:add(buffer(8+srclen,dstlen),"Destination adress: " .. dstaddr)
	srcdst_tree:add(buffer(CMN_HDR_LEN,srclen),"Source adress: " .. srcaddr .. ", ISD_ID:" .. src_isd_id .. ", AD_ID:" .. src_ad_id .. ", HOST Adress:" .. srcaddr_host_text)
	srcdst_tree:add(buffer(CMN_HDR_LEN+srclen,dstlen),"Destination adress: " .. dstaddr .. ", ISD_ID:" .. dst_isd_id .. ", AD_ID:" .. dst_ad_id .. ", HOST Adress:" .. dstaddr_host_text)
	--srcdst_tree:add(buffer(8+srclen,dstlen),"Destination adress: " .. dstaddr)

	--analyze opaque field
	process_of(buffer,pinfo,tree)
end

function process_beacon(buffer,pinfo,tree)
	-- TODO Update the code for supporting the latest version of PCB


	--analyze opaque field
	local of_field = ProtoField.string("of","Opaque field")
	local of_offset=CMN_HDR_LEN+srclen+dstlen;

	local of_tree = scion_tree:add(of_field,buffer(of_offset,16),"Opaque field ") --size = 16 (SOF and ROTOF)
	
	oftypename="Info OF"
	of_sof_tree=of_tree:add(buffer(of_offset,8),"Opaque filed type: " .. oftypename .. " (0x" .. string.format("%x",buffer(of_offset,1):uint()) .. ")")
	if timestamp + CMN_HDR_LEN   == of_offset then  
		of_sof_tree:append_text(", Current IOF")
	end
	if curr_of + CMN_HDR_LEN   == of_offset then  
		of_sof_tree:append_text(", Current OF")
	end
	of_sof_tree:add(buffer(of_offset+1,4),"Timestamp: " .. buffer(of_offset+1,4))
	of_sof_tree:add(buffer(of_offset+5,2),"ISD ID: " .. buffer(of_offset+5,2))
	of_sof_tree:add(buffer(of_offset+7,1),"Hops: " .. buffer(of_offset+7,1))



	of_offset=of_offset+8
	oftypename="ROT OF"
	of_rot_tree=of_tree:add(buffer(of_offset,8),"Opaque filed type: " .. oftypename .. " (0x" .. string.format("%x",buffer(of_offset,1):uint()) .. ")")
	if timestamp + CMN_HDR_LEN   == of_offset then  
		of_rot_tree:append_text(", Current IOF")
	end
	if curr_of + CMN_HDR_LEN   == of_offset then  
		of_rot_tree:append_text(", Current OF")
	end
	of_rot_tree:add(buffer(of_offset+1,2),"ROT version: " .. buffer(of_offset+1,2))
	of_rot_tree:add(buffer(of_offset+3,2),"ISD ID: " .. buffer(of_offset+3,2))
	of_rot_tree:add(buffer(of_offset+6,2),"Reserved: " .. buffer(of_offset+6,2))


	--Segment ID
	of_offset=of_offset+8
	of_segment_tree=of_tree:add(buffer(of_offset,32),"Segment ID = " ..  buffer(of_offset,32))
	of_offset=of_offset+32


	--PCBMarking
	local pcb_size=32
	local pcb_tree = scion_tree:add(buffer(of_offset,hdr_len - of_offset),"PCB")
--	for of_offset=of_offset+8, of_offset + pcb_size < hdr_len, pcb_size do
	of_offset = of_offset + 8
	
	--num_pcb = (hdr_len - of_offset)/pcb_size
	--num_pcb = (buffer:len() - of_offset)/pcb_size
	num_pcb=1	

	--scion_tree:add_expert_info(PI_MALFORMED, PI_ERROR, hdr_len .. ", " .. of_offset .. ", " .. pcb_size .. ", " .. buffer:len())
	
	for i=0, num_pcb-1, 1 do
		local pcbsub_tree = pcb_tree:add(buffer(of_offset,pcb_size),"PCB Marking ".. i)

		pcbsub_tree:add(buffer(of_offset,8),"AD ID: " .. buffer(of_offset,8))

		local ssf_tree=pcbsub_tree:add(buffer(of_offset+8,8),"Support signature field: " .. buffer(of_offset+8,8))
		ssf_tree:add(buffer(of_offset+8,4),"Certificate ID: " .. buffer(of_offset+8,4))
		ssf_tree:add(buffer(of_offset+8+4,2),"Signature length: " .. buffer(of_offset+8+4,2))
		ssf_tree:add(buffer(of_offset+8+6,2),"Block size: " .. buffer(of_offset+8+6,2))
		local signature_length= buffer(of_offset+8+4,2):uint()
		local signature_length= buffer(of_offset+8+6,2):uint()

--[[
Each hop opaque field has a info (8 bits), expiration time (8 bits)
    ingress/egress interfaces (2 * 12 bits) and a MAC (24 bits) authenticating
    the opaque fiel
--]]
		local hof_tree=pcbsub_tree:add(buffer(of_offset+16,8),"Hop opaque field: " .. buffer(of_offset+16,8))
		hof_tree:add(buffer(of_offset+16,1),"Info: " .. buffer(of_offset+16,1))
		hof_tree:add(buffer(of_offset+16+1,1),"Expiration time: " .. buffer(of_offset+16+1,1):uint())
		local ingress_egress=buffer(of_offset+16+2,3):uint()
		local ingress_if=bit.rshift(ingress_egress,12)
		local egress_if=bit.band(ingress_egress,0x0fff)
		hof_tree:add(buffer(of_offset+16+2,3),"Ingress IF: " .. ingress_if)
		hof_tree:add(buffer(of_offset+16+2,3),"Egress IF: " .. egress_if)
		hof_tree:add(buffer(of_offset+16+5,3),"MAC: " .. buffer(of_offset+16+5,3))
	
		local spf_tree=pcbsub_tree:add(buffer(of_offset+24,8),"Support PCB field: " .. buffer(of_offset+24,8))
		spf_tree:add(buffer(of_offset+24,2),"ISD ID: " .. buffer(of_offset+24,2))
		spf_tree:add(buffer(of_offset+24+2,1),"Bandwidth allocation F: " .. buffer(of_offset+24+2,1))
		spf_tree:add(buffer(of_offset+24+3,1),"Bandwidth allocation R: " .. buffer(of_offset+24+3,1))
		spf_tree:add(buffer(of_offset+24+4,1),"Dynamic bandwidth allocation F: " .. buffer(of_offset+24+4,1))
		spf_tree:add(buffer(of_offset+24+5,1),"Dynamic bandwidth allocation R: " .. buffer(of_offset+24+5,1))
		spf_tree:add(buffer(of_offset+24+6,1),"BE bandwidth F: " .. buffer(of_offset+24+6,1))
		spf_tree:add(buffer(of_offset+24+7,1),"BE bandwidth R: " .. buffer(of_offset+24+7,1))


		of_offset = of_offset + pcb_size

		-- process Peer Marking
		pear_marking_size = 24
		local j=0
		while of_offset + pear_marking_size < buffer:len() do
			local pcbsub_tree = pcb_tree:add(buffer(of_offset,pear_marking_size),"Peer Marking ".. j)
			
			pcbsub_tree:add(buffer(of_offset,8),"AD ID: " .. buffer(of_offset,8))

			offset_hof=8
			local hof_tree=pcbsub_tree:add(buffer(of_offset+offset_hof,8),"Hop opaque field: " .. buffer(of_offset+offset_hof,8))
			hof_tree:add(buffer(of_offset+offset_hof,1),"Info: " .. buffer(of_offset+offset_hof,1))
			hof_tree:add(buffer(of_offset+offset_hof+1,1),"Expiration time: " .. buffer(of_offset+offset_hof+1,1):uint())
			local ingress_egress=buffer(of_offset+offset_hof+2,3):uint()
			local ingress_if=bit.rshift(ingress_egress,12)
			local egress_if=bit.band(ingress_egress,0x0fff)
			hof_tree:add(buffer(of_offset+offset_hof+2,3),"Ingress IF: " .. ingress_if)
			hof_tree:add(buffer(of_offset+offset_hof+2,3),"Egress IF: " .. egress_if)
			hof_tree:add(buffer(of_offset+offset_hof+5,3),"MAC: " .. buffer(of_offset+offset_hof+5,3))
		
			pcbsub_tree:append_text(", Ingress IF: " .. buffer(of_offset+offset_hof+1,2):uint() .. ", Egress IF: " .. buffer(of_offset+offset_hof+3,2))

			offset_spf=16
			local spf_tree=pcbsub_tree:add(buffer(of_offset+offset_spf,8),"Support PCB field: " .. buffer(of_offset+offset_spf,8))
			spf_tree:add(buffer(of_offset+offset_spf,2),"ISD ID: " .. buffer(of_offset+offset_spf,2))
			spf_tree:add(buffer(of_offset+offset_spf+2,1),"Bandwidth allocation F: " .. buffer(of_offset+offset_spf+2,1))
			spf_tree:add(buffer(of_offset+offset_spf+3,1),"Bandwidth allocation R: " .. buffer(of_offset+offset_spf+3,1))
			spf_tree:add(buffer(of_offset+offset_spf+4,1),"Dynamic bandwidth allocation F: " .. buffer(of_offset+offset_spf+4,1))
			spf_tree:add(buffer(of_offset+offset_spf+5,1),"Dynamic bandwidth allocation R: " .. buffer(of_offset+offset_spf+5,1))
			spf_tree:add(buffer(of_offset+offset_spf+6,1),"BE bandwidth F: " .. buffer(of_offset+offset_spf+6,1))
			spf_tree:add(buffer(of_offset+offset_spf+7,1),"BE bandwidth R: " .. buffer(of_offset+offset_spf+7,1))

			j=j+1
			of_offset = of_offset + pear_marking_size
		end

		pcb_tree:add_expert_info(PI_DEBUG,PI_CHAT,"dummy")
	end

end


function process_of(buffer,pinfo,tree)
--Opaque field

	local num_op= (hdr_len - 24)/OPAQUEFIELD_LEN -- num_op= hops in special opaque field
	local i=0
	while i <  num_op do
		local of_offset=8+srclen+dstlen + OPAQUEFIELD_LEN*i

		--check range
		if of_offset + OPAQUEFIELD_LEN > hdr_len then
			scion_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "cannot read opaque field. Hdr_len is small?")
			return
		end


		local of_field = ProtoField.string("of"..i,"Opaque field"..i)
		local of_tree = scion_tree:add(of_field,buffer(of_offset,OPAQUEFIELD_LEN),"Opaque field ".. i)

		
		--check OF type
		local oftype=buffer(of_offset,1):uint()
		local oftypename="???"

		-- Hop OF
		NORMAL_OF = 0x0
		LAST_OF = 0x10
		PEER_XOVR = 0x08

		-- Info OF
		TDC_XOVR=0x40
		NON_TDC_XOVR=0x60
		INPATH_XOVR=0x70
		INTRATD_PEER=0x78
		INTERTD_PEER=0x7c

		-- MSB 7bit
		local oftype=bit.rshift(oftype,1) 

		--is Info OF?
		if oftype == TDC_XOVR or oftype == NON_TDC_XOVR or oftype == INPATH_XOVR or iftype ==  INTRATD_PEER or oftype == INTERTD_PEER or oftype == TRC_OF then
			if oftype == TDC_XOVR then
				oftypename="Info OF TDC_XOVER"
			elseif oftype == NON_TDC_XOVR then
				oftypename="Info OF NON_TDC_XOVR"
			elseif oftype == INPATH_XOVR then
				oftypename="Info OF INPATH_XOVR"
			elseif oftype == INTRATD_PEER then
				oftypename="Info OF INTRATD_PEER"
			elseif oftype == INTERTD_PEER then
				oftypename="Info OF INTERTD_PEER"
			end


			of_tree:append_text(", Info OF")
			of_tree:add(buffer(of_offset,1),"Opaque filed type: " .. oftypename .. " (0x" .. string.format("%x",oftype) .. ")")
			of_tree:add(buffer(of_offset+1,4),"Timestamp: " .. buffer(of_offset+1,4))
			of_tree:add(buffer(of_offset+5,2),"ISD ID: " .. buffer(of_offset+5,2))
			of_tree:add(buffer(of_offset+7,1),"Hops: " .. buffer(of_offset+7,1))
			
			--num_op = num_op + buffer(of_offset+7,1):uint() -- plus hops


		--Hop OF
		else
			if oftype==NORMAL_OF then
				oftypename="NORMAL_OF"
			elseif oftype == LAST_OF then
				oftypename="LAST_OF"
			elseif oftype == PEER_XOVR then
				oftypename="PEER_XOVR"
			end
			
			of_tree:add(buffer(of_offset,1),"Opaque filed type: " .. oftypename .. " (0x" .. string.format("%x",buffer(of_offset,1):uint()) .. ")" )
			local ingress_egress=buffer(of_offset+2,3):uint()
			local ingress_if=bit.rshift(ingress_egress,12)
			local egress_if=bit.band(ingress_egress,0x0fff)
			of_tree:append_text(", Ingress IF: " .. ingress_if .. ", Egress IF: " .. egress_if)
			of_tree:add(buffer(of_offset+1,1),"Expiration time: " .. buffer(of_offset+1,1):uint())
			of_tree:add(buffer(of_offset+2,3),"Ingress IF: " .. ingress_if)
			of_tree:add(buffer(of_offset+2,3),"Egress IF: " .. egress_if)
			of_tree:add(buffer(of_offset+5,3),"MAC: " .. buffer(of_offset+5,3))

		end

		
		--check timestamp field and curr OF field refer this OF
		if timestamp + CMN_HDR_LEN   == of_offset then 
			of_tree:append_text(", Current IOF")
		end
		if curr_of + CMN_HDR_LEN   == of_offset then   
			of_tree:append_text(", Current OF")
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
		PacketType.CERT_CHAIN_REP: 33611786,
		PacketType.PATH_REP_LOCAL: 50389002,
		PacketType.PATH_REP: 67166218,
		PacketType.PATH_REP_TDC: 83943434,
		PacketType.ROT_REP_LOCAL:100720650,
		PacketType.OFG_KEY_REP: 117497866,
		PacketType.ROT_REP: 134275082,
		PacketType.CERT_CHAIN_REP_LOCAL:151052298,
		PacketType.IFID_REP: 167829514,
		PacketType.UP_PATH: 33612000,
		}
TYPES_SRC_INV = {v: k for k, v in TYPES_SRC.items()}
TYPES_DST = {
		PacketType.CERT_CHAIN_REQ: 33611786,
		PacketType.PATH_REQ_LOCAL:50389002,
		PacketType.PATH_REQ: 67166218,
		PacketType.PATH_REQ_TDC: 83943434,
		PacketType.ROT_REQ_LOCAL: 100720650,
		PacketType.OFG_KEY_REQ: 117497866,
		PacketType.ROT_REQ: 134275082,
		PacketType.CERT_CHAIN_REQ_LOCAL: 151052298,
		PacketType.UP_PATH: 33612000,
		PacketType.PATH_REG: 50389216,
		PacketType.IFID_REQ: 167829514,
	}
--]]
	if src_addr==16834570 then
		return "BEACON"
	elseif src_addr==33611786 then
		return "CERT_CHAIN_REP"
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
		return "CERT_CHAIN_REP_LOCAL"
	elseif src_addr==167829514 then
		return "IFID_REP"
	elseif src_addr==33612000 then
		return "UP_PATH"
	end
	
	if dst_addr==33611786 then
		return "CERT_CHAIN_REQ"
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
		return "CERT_CHAIN_REQ_LOCAL"
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
--assume UDP 30040 is for SCION
table_udp=DissectorTable.get("udp.port")
table_udp:add(30040,scion_proto)
--for i=30040,30040, 1 do
--	table_udp:add(i,scion_proto)
--end
