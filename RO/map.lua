local packets = {};

-- -----------------------------------------------------------------------------
-- Protocol Definition ---------------------------------------------------------
-- -----------------------------------------------------------------------------
local ro = Proto("ro.map", "Map Server"); -- [ro.map]


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
	pkt.cols.info:set(string.format("[LOGIN] %s", pkt_name));
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
-- login_connect
function login_connect(type, buf, pkt, tree)
	local len = buf:len();
	-- TODO: Handle different types.
	-- TODO: Handle insufficient packet length.
	-- request client login (raw password)
	--	case 0x0064: // S 0064 <version>.L <username>.24B <password>.24B <clienttype>.B
	--	case 0x0277: // S 0277 <version>.L <username>.24B <password>.24B <clienttype>.B <ip address>.16B <adapter address>.13B
	--	case 0x02b0: // S 02b0 <version>.L <username>.24B <password>.24B <clienttype>.B <ip address>.16B <adapter address>.13B <g_isGravityID>.B
	--	request client login (md5-hashed password)
	--	case 0x01dd: // S 01dd <version>.L <username>.24B <password hash>.16B <clienttype>.B
	--	case 0x01fa: // S 01fa <version>.L <username>.24B <password hash>.16B <clienttype>.B <?>.B(index of the connection in the clientinfo file (+10 if the command-line contains "pc"))
	--	case 0x027c: // S 027c <version>.L <username>.24B <password hash>.16B <clienttype>.B <?>.13B(junk)
	--	case 0x0825: // S 0825 <packetsize>.W <version>.L <clienttype>.B <userid>.24B <password>.27B <mac>.17B <ip>.15B <token>.(packetsize - 0x5C)B
	local offset = 0;

	tree:add(f_version, buf(offset, 4)); offset = offset + 4;
	tree:add(f_user, buf(offset, 24), 
		string.format("Username: %s", buf(offset, 24):string())); offset = offset + 24;
	tree:add(f_pass, buf(offset, 24), 
		string.format("Password: %s", buf(offset, 24):string())); offset = offset + 24;
	tree:add(f_clienttype, buf(offset, 1)); offset = offset + 1;
end

-- login_auth_ok
function login_auth_ok(type, buf, pkt, tree)
	local len = buf:len();
	local offset = 0;
	tree:add(f_servernum, buf(offset, 2), (buf(offset, 2):le_uint()-47)/32); offset = offset + 2;
	tree:add(f_login_id, buf(offset, 4)); offset = offset + 4;
	tree:add(f_account_id, buf(offset, 4)); offset = offset + 4;
	tree:add(f_login_id2, buf(offset, 4)); offset = offset + 4;
	offset = offset + 16; -- Unused `IP` field.
	offset = offset + 24; -- Unused `Name` field.
	offset = offset +  2; -- Unknown word.
	tree:add(f_gender, buf(offset,1)); offset = offset + 1;

	-- Dissect the list of char servers.
	local server_count = (len-offset)/32
	tree:append_text("Server Count: "..server_count);

end

function void_dissect(type, buf, pkt, tree)
	tree:append_
end

-- PACKET TABLE ----------------------------------------------------------------
packets[0x0064] = { name = "request_login", dissect = login_connect};
--packets[0x0277] = { name = "request_login", dissect = login_connect};
packets[0x0069] = { name = "login_auth_ok", dissect = login_auth_ok};

-- ZC

-- REGISTER --------------------------------------------------------------------
local tcpt = DissectorTable.get( "tcp.port" );
tcpt:add(6121, ro);