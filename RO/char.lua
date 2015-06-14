local packets = {};

-- -----------------------------------------------------------------------------
-- Protocol Definition ---------------------------------------------------------
-- -----------------------------------------------------------------------------
local ro = Proto("ro.char", "Character Server"); -- [ro.char]
local f_type       = ProtoField.uint16("ro.char.type", "Message Type", base.HEX); table.insert(ro.fields, f_type);
local f_payload    = ProtoField.bytes("ro.char.data", "Payload"); table.insert(ro.fields, f_payload);

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
	pkt.cols.info:set(string.format("[CHAR] %s", pkt_name));
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
-- Game Guard
packets[0x03dd] = { name = "AHC_GAME_GUARD", dissect = void_d };
packets[0x03de] = { name = "CAH_ACK_GAME_GUARD", dissect = void_d };

-- Client -> Char
packets[0x0065] = { name = "CH_ENTER", dissect = void_d }; -- Returns account ID.
packets[0x0066] = { name = "CH_SELECT_CHAR", dissect = void_d };
packets[0x0067] = { name = "CH_MAKE_CHAR", dissect = void_d };
packets[0x0068] = { name = "CH_DELETE_CHAR", dissect = void_d };
packets[0x09a1] = { name = "CH_REQ_CHARLIST", dissect = void_d };

-- Char -> Client
packets[0x006b] = { name = "HC_ACCEPT_ENTER_NEO_UNION", dissect = void_d };
packets[0x006c] = { name = "HC_REFUSE_ENTER", dissect = void_d };
packets[0x006d] = { name = "HC_ACCEPT_MAKECHAR_NEO_UNION", dissect = void_d };
packets[0x006e] = { name = "HC_REFUSE_MAKECHAR", dissect = void_d };
packets[0x006f] = { name = "HC_ACCEPT_DELETECHAR", dissect = void_d };
packets[0x0070] = { name = "HC_REFUSE_DELETECHAR", dissect = void_d };
packets[0x0071] = { name = "HC_NOTIFY_ZONESVR", dissect = void_d };
packets[0x0187] = { name = "HC_PING", dissect = void_d };
packets[0x020d] = { name = "HC_BLOCK_CHARACTER", dissect = void_d };
packets[0x023e] = { name = "HC_REQUEST_CHARACTER_PASSWORD", dissect = void_d };
packets[0x02ca] = { name = "HC_REFUSE_SELECTCHAR", dissect = void_d };
packets[0x0448] = { name = "HC_CHARACTER_LIST", dissect = void_d };
packets[0x07e8] = { name = "HC_CHECKBOT", dissect = void_d };
packets[0x07e9] = { name = "HC_CHECKBOT_RESULT", dissect = void_d };
packets[0x028e] = { name = "HC_ACK_IS_VALID_CHARNAME", dissect = void_d };
packets[0x0290] = { name = "HC_ACK_CHANGE_CHARNAME", dissect = void_d };
packets[0x0828] = { name = "HC_DELETE_CHAR3_RESERVED", dissect = void_d };
packets[0x082a] = { name = "HC_DELETE_CHAR3", dissect = void_d };
packets[0x082c] = { name = "HC_DELETE_CHAR3_CANCEL", dissect = void_d };
packets[0x082d] = { name = "HC_ACCEPT_ENTER_NEO_UNION_HEADER", dissect = void_d };
packets[0x0840] = { name = "HC_NOTIFY_ACCESSIBLE_MAPNAME", dissect = void_d };
packets[0x099d] = { name = "HC_ACCEPT_ENTER_NEO_UNION_LIST", dissect = void_d };
packets[0x09a0] = { name = "HC_CHARLIST_NOTIFY", dissect = void_d };
-- REGISTER --------------------------------------------------------------------
local d = DissectorTable.get( "ro.port" );
d:add(6121, ro);