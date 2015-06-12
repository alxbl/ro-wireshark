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

-- -----------------------------------------------------------------------------
-- Wireshark Dissector for Ragnarok Online Network Protocol
-- -----------------------------------------------------------------------------
-- Protocol Definition.
--local msg_handlers = {}; -- Type -> Dissector
--local msg_types = {};    -- Type -> String

--local ro = Proto("ro", "Ragnarok Online"); -- [ro]
dofile("G:/dev/re/ro/dissect/login.lua")

--local ro_char = Proto("ro.char", "Char Server"); -- [ro.char]
--local ro_map = Proto("ro.map", "Map Server"); -- [ro.map]

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

--------------------------------------------------------------------------------
-- REGISTER
--------------------------------------------------------------------------------
--tcpt:add(5121, ro_char);
--tcpt:add(6121, ro_map);
--------------------------------------------------------------------------------