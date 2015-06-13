-- Copyright (c) 2015 Alexandre Beaulieu <alex@segfault.me>

-- ro.lua is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

-- Disclaimer: I am Lua noob.

-- Base Packet Format ----------------------------------------------------------
-- RO packets are very simple and use a 2 byte identifier. The packet structure
-- is pre-defined on both ends based on those two bytes.
--
-- +---------+-----------------+
-- | 2 bytes | N bytes         |
-- +---------+-----------------+
-- | Type    | ... Payload ... |
-- +---------+-----------------+
--
-- -----------------------------------------------------------------------------
local LOGIN_PORT = 6900;
local CHAR_PORT = 6121;
local MAP_PORT = 5121;

-- Top level dissector.
local ro = Proto("ro", "Ragnarok Online"); -- [ro]
dissectors = DissectorTable.new("ro.port", "ro.port");

-- Individual dissectors.
dofile("/RO/login.lua");
dofile("/RO/map.lua");
dofile("/RO/char.lua");

-- Retrieve sub-dissectors.
--local login_dissect = dissectors:get_dissector("login");
--local map_dissect = dissectors:get_dissector("map");
--local char_dissect = dissectors:get_dissector("char");

--info(login_dissect);

function ro.dissector(buf, pkt, tree) -- Don't dissect, let the sub-dissectors work.
--	if pkt.cols.src_port == LOGIN_PORT and login_dissect then login_dissect(buf, pkt, tree);
--	elseif pkt.cols.src_port == CHAR_PORT and char_dissect then char_dissect(buf, pkt, tree);
--	elseif pkt.cols.src_port == MAP_PORT and map_dissect then map_dissect(buf, pkt, tree);
--	end
end

local tcpt = DissectorTable.get( "tcp.port" );
tcpt:add(LOGIN_PORT, dissectors:get_dissector(6900));
tcpt:add(CHAR_PORT, dissectors:get_dissector(6121));
tcpt:add(MAP_PORT, dissectors:get_dissector(5121));