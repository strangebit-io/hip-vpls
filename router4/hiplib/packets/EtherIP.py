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

ETHER_IP_VERSION     = 0x3
VERSION_OFFSET       = 0x0;
VERSION_LENGTH       = 0x1;
HEADER_LENGTH        = 0x2;
ETHER_IP_PROTO       = 97;

class EtherIP():
    def __init__(self, buffer = None):
        self.buffer = bytearray([0, ETHER_IP_VERSION]);
    
    def get_buffer(self):
        return self.buffer;