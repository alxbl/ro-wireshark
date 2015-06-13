local packets = {};

-- -----------------------------------------------------------------------------
-- Protocol Definition ---------------------------------------------------------
-- -----------------------------------------------------------------------------
local ro = Proto("ro.map", "Map Server"); -- [ro.map]
local f_type       = ProtoField.uint16("ro.map.type", "Message Type", base.HEX); table.insert(ro.fields, f_type);
local f_payload    = ProtoField.bytes("ro.map.data", "Payload"); table.insert(ro.fields, f_payload);

-- Dissector Entry Point -------------------------------------------------------
function ro.dissector(buf, pkt, tree)
	local pkt_type = 0;
	local len = buf:len();
	local offset = 0;
	
	-- Handle Packet Segmentation
	if (len < 2) then
		-- Need one more segment to read a PDU. Very unlikely to happen since the
		-- implementations appear to set PSH on every packet.
		info(string.format("Frame #%d @ %d/%d: Not enough data to read a PDU. Desegmenting one more segment.", pkt.number, offset, len));
		pkt.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
		pkt.desegment_offset = 0
		return;
	end

	-- Get the packet type
	pkt_type = buf(0, 2):le_uint();
	local pkt_name = "unknown_packet";
	pkt.cols.protocol	= "RO";

	-- Build the top level tree. (PDU, Packet Type, Packet Name)
	local t = tree:add(ro, buf(0, len), "PDU");
	local dissect_pkt = nil;
	if (packets[pkt_type]) then
		pkt_name = packets[pkt_type].name;
		dissect_pkt = packets[pkt_type].dissect;
	end
	pkt.cols.info:set(string.format("[MAP] %s", pkt_name));
	t:add(f_type, buf(0, 2),  pkt_type, string.format("Type: 0x%04x (%s)", pkt_type, pkt_name));

	-- Dissect the specific packet.
	local payload = buf(2, len-2);
	if (dissect_pkt) then
		dissect_pkt(pkt_type, payload:tvb(), pkt, t);
	else
		t:add(f_payload, payload); -- Raw payload.
	end 
end

-- PACKET DEFINITION -----------------------------------------------------------
function void_d(type, buf, pkt, tree)
end

-- PACKET TABLE ----------------------------------------------------------------
-- REGISTER --------------------------------------------------------------------
local d = DissectorTable.get( "ro.port" );
d:add(5121, ro);