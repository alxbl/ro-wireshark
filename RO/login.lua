local packets = {};

-- -----------------------------------------------------------------------------
-- Protocol Definition ---------------------------------------------------------
-- -----------------------------------------------------------------------------
-- Login Server Packets
local ro = Proto("ro.login", "Login Server"); -- [ro.login]
local f_type       = ProtoField.uint16("ro.login.type", "Message Type", base.HEX); table.insert(ro.fields, f_type);
local f_payload    = ProtoField.bytes("ro.login.data", "Payload"); table.insert(ro.fields, f_payload);
local f_version    = ProtoField.uint32("ro.login.version", "Version"); table.insert(ro.fields, f_version);
local f_login_id   = ProtoField.uint32("ro.login.id", "Login ID", base.HEX_DEC); table.insert(ro.fields, f_login_id);
local f_login_id2  = ProtoField.uint32("ro.login.id2", "Login ID2", base.HEX_DEC); table.insert(ro.fields, f_login_id2);
local f_account_id = ProtoField.uint32("ro.login.aid", "Account ID", base.HEX_DEC); table.insert(ro.fields, f_account_id);
local f_user       = ProtoField.bytes("ro.login.user", "Username"), table.insert(ro.fields, f_user);
local f_pass       = ProtoField.bytes("ro.login.pass", "Password"), table.insert(ro.fields, f_password);
local f_clienttype = ProtoField.uint8("ro.login.client_type", "Client Type"); table.insert(ro.fields, f_clienttype);
-- local f_clientip   = ProtoField.ipv6("ro.login.client_ip", "Client IP"); table.insert(ro.fields, f_clientip);
-- local f_hwaddr     = ProtoField.ether("ro.login.hw_addr", "Client MAC"); table.insert(ro.fields, f_hwaddr);
local f_servernum  = ProtoField.uint16("ro.login.servernum", "Server Number"); table.insert(ro.fields, f_servernum);
local f_gender     = ProtoField.uint8("ro.login.gender", "Gender"); table.insert(ro.fields, f_gender);
local f_refusal    = ProtoField.uint8("ro.login.refusal", "Refusal Reason"); table.insert(ro.fields, f_refusal);

-- Character Server List by login Server.
local ro_server = Proto("ro.login.server", "Character Server Record"); -- [ro.login.server]
local f_server_addr = ProtoField.ipv4("ro.login.server.addr", "Address");
local f_server_port = ProtoField.uint16("ro.login.server.port", "Port");
local f_server_name = ProtoField.string("ro.login.server.name", "Name");
local f_server_users = ProtoField.uint16("ro.login.server.users", "Users");
local f_server_type = ProtoField.uint16("ro.login.server.type", "Type");
local f_server_new  = ProtoField.uint16("ro.login.server.new", "New");
ro_server.fields = {f_server_addr, f_server_port, f_server_name, f_server_users, f_server_type, f_server_new};

function ro_server.dissector(buf, pkt, tree)
    local len = buf:len();
    local offset = 0;
    while (len - offset >= 32) do
        local s = tree:add(ro_server, buf(offset, 32), "Character Server");

        local ip = buf(offset, 4);    offset = offset + 4;
        local port = buf(offset, 2);  offset = offset + 2;
        local name = buf(offset, 20); offset = offset + 20;
        local users = buf(offset, 2); offset = offset + 2;
        local type = buf(offset, 2);  offset = offset + 2;
        local new = buf(offset, 2);   offset = offset + 2;
        --                                            = 32
        s:add(f_server_addr, ip);   
        s:add_le(f_server_port, port);   
        s:add(f_server_name, name);            
        s:add_le(f_server_users, users); 
        s:add(f_server_type, type);    
        s:add(f_server_new, new);     
        s:append_text(string.format(": %s (%s:%s) [%s]", name:string(), ip:ipv4(), port:le_uint(), users:le_uint()));
    end
end

-- Dissector Entry Point -------------------------------------------------------
function ro.dissector(buf, pkt, tree)
    local pkt_type = 0;
    local len = buf:len(); -- Length of the TCP payload.
    local offset = 0;
    
    -- Handle Packet Segmentation
    if (len < 2) then
        -- Need one more segment to read a PDU. Very unlikely to happen.
        info(string.format("Frame #%d @ %d/%d: Not enough data to read a PDU. Desegmenting one more segment.", pkt.number, offset, len));
        pkt.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        pkt.desegment_offset = 0
        return;
    end

    -- Get the packet type
    pkt_type = buf(0, 2):le_uint();
    local pkt_name = "unknown_packet";
    pkt.cols.protocol   = "RO";

    -- Build the top level tree. (PDU, Packet Type, Packet Name)
    local dissect_pkt = nil;
    if (packets[pkt_type]) then
        pkt_name = packets[pkt_type].name;
        dissect_pkt = packets[pkt_type].dissect;
    end

    local t = tree:add(ro, buf(0, len), pkt_name);
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
function login_connect(type, buf, pkt, tree)
    local len = buf:len();
    -- TODO: Handle insufficient packet length.
    local offset = 0;

    tree:add(f_version, buf(offset, 4)); offset = offset + 4;
    local username = buf(offset, 24):string();
    tree:add(f_user, buf(offset, 24), 
        string.format("Username: %s", username)); offset = offset + 24;
    tree:add(f_pass, buf(offset, 24), 
        string.format("Password: %s", buf(offset, 24):string())); offset = offset + 24;
    tree:add(f_clienttype, buf(offset, 1)); offset = offset + 1;
    pkt.cols.info:append(" User=" .. username);
end

function login_auth_ok(type, buf, pkt, tree)
    local len = buf:len();
    local offset = 0;
    tree:add(f_servernum, buf(offset, 2), (buf(offset, 2):le_uint()-47)/32); offset = offset + 2;
    local aid  = buf(offset, 4); offset = offset + 4;
    local lid1 = buf(offset, 4); offset = offset + 4;
    local lid2 = buf(offset, 4); offset = offset + 4;
    tree:add_le(f_login_id, lid1);
    tree:add_le(f_account_id, aid); 
    tree:add_le(f_login_id2, lid2);
    
    offset = offset + 4; -- Unused `IP` field.
    offset = offset + 24; -- Unused `Name` field.
    offset = offset +  2; -- Unknown word.
    
    pkt.cols.info:append(string.format(" Login1=%d, Account=0x%x, Login2=0x%x", 
        lid1:le_uint(), aid:le_uint(), lid2:le_uint()));
    tree:add(f_gender, buf(offset,1)); offset = offset + 1;
    
    -- Dissect the list of char servers.
    ro_server.dissector(buf(offset):tvb(), pkt, tree);
end

function login_failed(type, buf, pkt, tree)
    local code = buf(0,1):uint();
    local reason = "unknown reason";
    if (type == 0x0081) then -- Login Failure
        if     code == 1 then reason = "server closed";
        elseif code == 8 then reason = "server still recognizes your last login";
        end
    elseif (type == 0x006a or type == 0x083e) then -- Authentication Error
        if     code == 0   then reason = "Unregistered ID";
        elseif code == 1   then reason = "Incorrect password";
        elseif code == 2   then reason = "Account expired";
        elseif code == 3   then reason = "Rejected from server";
        elseif code == 4   then reason = "Blocked by GM";
        elseif code == 5   then reason = "Invalid game client version";
        elseif code == 6   then reason = "Banned until"; -- TODO: Dissect the date as well.
        elseif code == 7   then reason = "Server full";
        elseif code == 8   then reason = "Account limit reached";
        elseif code == 9   then reason = "Banned by DBA";           
        elseif code == 10  then reason = "E-mail not confirmed";
        elseif code == 11  then reason = "Banned by GM";
        elseif code == 12  then reason = "Maintenance"; -- MSI_REFUSE_TEMP_BAN_FOR_DBWORK
        elseif code == 13  then reason = "Account Locked"; -- Too many failed logins
        elseif code == 14  then reason = "Not permitted group"; -- ??
        elseif code == 15  then reason = "Not permitted group"; -- ??
        elseif code == 99  then reason = "Account data deleted";
        elseif code == 100 then reason = "Login info remains"; -- ??
        elseif code == 101 then reason = "Hacking investigation";
        elseif code == 102 then reason = "Bug investigation";
        elseif code == 103 then reason = "Character being deleted";
        elseif code == 104 then reason = "Spouse character being deleted";
        end
    end
    pkt.cols.info:append(" Reason="..reason);

end

-- void dissector for unimplemented packets. 
-- Display their name and type, but do not process information any further.
function void_d(type, buf, pkt, tree)
end

-- PACKET TABLE ----------------------------------------------------------------
-- Client -> Login
-- Raw Pass (Packets taken from eAthena)
packets[0x0064] = { name = "CA_REQUEST_LOGIN_RAW", dissect = login_connect}; -- S 0064 <version>.L <username>.24B <password>.24B <clienttype>.B
packets[0x0277] = { name = "CA_REQUEST_LOGIN_RAW", dissect = login_connect}; -- S 0277 <version>.L <username>.24B <password>.24B <clienttype>.B <ip address>.16B <adapter address>.13B
packets[0x02b0] = { name = "CA_REQUEST_LOGIN_RAW", dissect = login_connect}; -- S 02b0 <version>.L <username>.24B <password>.24B <clienttype>.B <ip address>.16B <adapter address>.13B <g_isGravityID>.B
-- MD5 Hash
packets[0x01dd] = { name = "CA_REQUEST_LOGIN_MD5", dissect = login_connect}; -- S 01dd <version>.L <username>.24B <password hash>.16B <clienttype>.B
packets[0x01fa] = { name = "CA_REQUEST_LOGIN_MD5", dissect = login_connect}; -- S 01fa <version>.L <username>.24B <password hash>.16B <clienttype>.B <?>.B(index of the connection in the clientinfo file (+10 if the command-line contains "pc"))
packets[0x027c] = { name = "CA_REQUEST_LOGIN_MD5", dissect = login_connect}; -- S 027c <version>.L <username>.24B <password hash>.16B <clienttype>.B <?>.13B(junk)
packets[0x0825] = { name = "CA_REQUEST_LOGIN_MD5", dissect = login_connect}; -- S 0825 <packetsize>.W <version>.L <clienttype>.B <userid>.24B <password>.27B <mac>.17B <ip>.15B <token>.(packetsize - 0x5C)B

packets[0x0204] = { name = "CA_EXE_HASHCHECK", dissect = void_d };

-- Login -> Client
packets[0x0069] = { name = "AC_ACCEPT_LOGIN", dissect = login_auth_ok};
packets[0x0081] = { name = "AC_REFUSE_LOGIN", dissect = login_failed}; -- Login Error
packets[0x006a] = { name = "AC_REFUSE_LOGIN", dissect = login_failed}; -- Refuse Login
packets[0x083e] = { name = "AC_REFUSE_LOGIN", dissect = login_failed}; -- Refuse Login R2

-- Un-dissected (TODO)
packets[0x01dc] = { name = "AC_ACK_HASH", dissect = void_d };
packets[0x01f1] = { name = "AC_NOTIFY_ERROR", dissect = void_d };
packets[0x023d] = { name = "AC_EVENT_RESULT", dissect = void_d };
packets[0x0259] = { name = "AC_ACK_GAME_GUARD", dissect = void_d };
packets[0x0261] = { name = "AC_REQ_LOGIN_OLDEKEY", dissect = void_d };
packets[0x0262] = { name = "AC_REQ_LOGIN_NEWEKEY", dissect = void_d };
packets[0x0263] = { name = "AC_REQ_LOGIN_CARDPASS", dissect = void_d };
packets[0x0267] = { name = "AC_ACK_EKEY_FAIL_NOTEXIST", dissect = void_d };
packets[0x0268] = { name = "AC_ACK_EKEY_FAIL_NOTUSESEKEY", dissect = void_d };
packets[0x0269] = { name = "AC_ACK_EKEY_FAIL_NOTUSEDEKEY", dissect = void_d };
packets[0x026a] = { name = "AC_ACK_EKEY_FAIL_AUTHREFUSE", dissect = void_d };
packets[0x026b] = { name = "AC_ACK_EKEY_FAIL_INPUTEKEY", dissect = void_d };
packets[0x026c] = { name = "AC_ACK_EKEY_FAIL_NOTICE", dissect = void_d };
packets[0x026d] = { name = "AC_ACK_EKEY_FAIL_NEEDCARDPASS", dissect = void_d };
packets[0x026e] = { name = "AC_ACK_AUTHEKEY_FAIL_NOTMATCHCARDPASS", dissect = void_d };
packets[0x026f] = { name = "AC_ACK_FIRST_LOGIN", dissect = void_d };
packets[0x0270] = { name = "AC_REQ_LOGIN_ACCOUNT_INFO", dissect = void_d };
packets[0x0272] = { name = "AC_ACK_PT_ID_INFO", dissect = void_d };
packets[0x02ad] = { name = "AC_REQUEST_SECOND_PASSWORD", dissect = void_d };
packets[0x03dd] = { name = "AHC_GAME_GUARD", dissect = void_d };
packets[0x03de] = { name = "CAH_ACK_GAME_GUARD", dissect = void_d };
packets[0x0821] = { name = "AC_OTP_USER", dissect = void_d };
packets[0x0823] = { name = "AC_OTP_AUTH_ACK", dissect = void_d };
packets[0x0826] = { name = "AC_SSO_LOGIN_ACK", dissect = void_d };

-- REGISTER --------------------------------------------------------------------
local d = DissectorTable.get( "ro.port" );
d:add(6900, ro);