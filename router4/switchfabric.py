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
from binascii import hexlify

class FIB():
    def __init__(self, file):
        self.fib_broadcast = [];
        self.fib_unicast = {};
        fd = open(file, "r")
        pairs = fd.readlines();
        for mesh_pair in pairs:
            parts = mesh_pair.split(" ")
            ihit = parts[0].replace(":", "")
            rhit = parts[1].replace(":", "")
            ihit = bytes.fromhex(ihit)
            rhit = bytes.fromhex(rhit)
            self.fib_broadcast.append((ihit, rhit));
    def get_next_hop(self, dmac):
        # Broadcast address
        if dmac[5] == 0xFF and dmac[4] == 0xFF and dmac[3] == 0xFF \
            and dmac[2] == 0xFF and dmac[1] == 0xFF and dmac[0] == 0xFF:
            logging.debug("Broadcast frame....")
            return self.fib_broadcast;
        logging.debug("Searching for the next hop")
        # Multicast address
        if dmac[5] & 0x1:
            logging.debug("Multicast frame....");
            return self.fib_broadcast;
        # Unicast
        dmac = hexlify(dmac).decode("ascii")
        logging.debug("Looking up by the destination MAC address")
        if not self.fib_unicast.get(dmac, None):
            return self.fib_broadcast;
        logging.debug("Message found in the FIB database")
        return [self.fib_unicast.get(dmac)];
            
    def set_next_hop(self, dmac, shit, rhit):
        # Broadcast address
        if dmac[5] == 0xFF and dmac[4] == 0xFF and dmac[3] == 0xFF \
            and dmac[2] == 0xFF and dmac[1] == 0xFF and dmac[0] == 0xFF:
            return;
        # Multicast address
        if dmac[5] & 0x1:
            return;
        dmac = hexlify(dmac).decode("ascii");
        self.fib_unicast[dmac] = (shit, rhit);

