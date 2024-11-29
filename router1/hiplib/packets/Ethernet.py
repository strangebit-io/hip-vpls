#!/usr/bin/python3

# Copyright (C) 2019 strangebit

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import logging

import copy

ETH_DEST_MAC_ADDRESS_OFFSET       = 0x0;
ETH_DEST_MAC_ADDRESS_LENGTH       = 0x6;

ETH_SOURCE_MAC_ADDRESS_OFFSET     = 0x6;
ETH_SOURCE_MAC_ADDRESS_LENGTH     = 0x6;

ETH_TYPE_OFFSET                   = 0xC;
ETH_TYPE_LENGTH                   = 0x2;

ETH_PAYLOAD_OFFSET                = 0xE;

ETH_CHECKSUM_OFFEST               = 0x0;
ETH_CHECKSUM_LENGTH               = 0x4;

MAX_ETHERNET_FRAME                = 0x05EE;

class EthernetFrame():
    def __init__(self, buffer = None):
        self.buffer = buffer;
    def get_type(self):
        buf = self.buffer[ETH_TYPE_OFFSET:ETH_TYPE_OFFSET + ETH_TYPE_LENGTH];
        return ((buf[1] << 8) & 0xFF00 | buf[0] & 0xFF)
    def set_type(self, type):
        pass
    def get_destination(self):
        return self.buffer[0:ETH_DEST_MAC_ADDRESS_LENGTH];
    def set_destination(self, macAddress):
        pass
    def get_source(self):
        return self.buffer[ETH_SOURCE_MAC_ADDRESS_OFFSET:ETH_SOURCE_MAC_ADDRESS_OFFSET + ETH_SOURCE_MAC_ADDRESS_LENGTH]; 
    def set_source(self, macAddress):
        pass
    def get_payload(self):
        pass
    def set_payload(self, payload):
        pass
    def get_checksum(self):
        return self.buffer[ETH_TYPE_OFFSET:-ETH_CHECKSUM_LENGTH];
    def set_checksum(self, checksum):
        pass
    def get_buffer(self):
        return self.buffer;