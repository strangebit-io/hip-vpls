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
        self.mac_firewall = {};
        self.fib_unicast = {};
        self.load_mesh(file);
    
    def load_mesh(self, file):
        self.fib_broadcast = [];
        fd = open(file, "r")
        pairs = fd.readlines();
        for mesh_pair in pairs:
            parts = mesh_pair.split(" ")
            ihit = parts[0].replace(":", "").strip()
            rhit = parts[1].replace(":", "").strip()
            ihit = bytes.fromhex(ihit)
            rhit = bytes.fromhex(rhit)
            self.fib_broadcast.append((ihit, rhit));
    
    def load_rules(self, file):
        self.mac_firewall = {}
        fd = open(file, "r")
        pairs = fd.readlines();
        for mac_pair in pairs:
            parts = mac_pair.split(" ")
            mac1 = parts[0].replace(":", "").strip()
            mac2 = parts[1].replace(":", "").strip()
            rule = parts[2].strip();
            mask = 1
            if rule != "allow":
                mask = 0
            if not self.mac_firewall.get(mac1, None):
                self.mac_firewall[mac1] = {
                    mac2: mask
                }
            else:
                self.mac_firewall[mac1][mac2] = mask
    def is_allowed(self, mac1, mac2):
        if not self.mac_firewall.get(mac1, None):
            return False
        if not self.mac_firewall[mac1].get(mac2, None):
            return False
        return self.mac_firewall[mac1][mac2] == 1
    
    def get_next_hop(self, dmac):
        
        # Broadcast address
        if dmac[5] == 0xFF and dmac[4] == 0xFF and dmac[3] == 0xFF \
            and dmac[2] == 0xFF and dmac[1] == 0xFF and dmac[0] == 0xFF:
            #logging.debug("Broadcast frame....")
            return self.fib_broadcast;
        #logging.debug("Searching for the next hop")
        # Multicast address
        if dmac[5] & 0x1:
            #logging.debug("Multicast frame....");
            return self.fib_broadcast;
        # Unicast
        #dmac = hexlify(dmac).decode("ascii")
        dmac = int.from_bytes(dmac, byteorder="little")
        #logging.debug("Looking up by the destination MAC address")
        hop = self.fib_unicast.get(dmac, None)
        if not hop:
            return self.fib_broadcast;
        #logging.debug("Message found in the FIB database")
        return [hop];
            
    def set_next_hop(self, dmac, shit, rhit):
        # Broadcast address
        if dmac[5] == 0xFF and dmac[4] == 0xFF and dmac[3] == 0xFF \
            and dmac[2] == 0xFF and dmac[1] == 0xFF and dmac[0] == 0xFF:
            return;
        # Multicast address
        if dmac[5] & 0x1:
            return;
        #dmac = hexlify(dmac).decode("ascii");
        dmac = int.from_bytes(dmac, byteorder="little")
        self.fib_unicast[dmac] = (shit, rhit);

