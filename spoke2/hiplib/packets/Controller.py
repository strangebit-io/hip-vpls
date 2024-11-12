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

CONTROLLER_PACKET_TYPE_OFFSSET = 0
CONTROLLER_LENGTH_OFFSET = 4
class ControllerPacket():
    def __init__(self, buffer):
        self.buffer = buffer
    def set_packet_type(self, type):
        self.buffer[CONTROLLER_PACKET_TYPE_OFFSSET] = (type >> 24) & 0xFF;
        self.buffer[CONTROLLER_PACKET_TYPE_OFFSSET + 1] = (type >> 16) & 0xFF;
        self.buffer[CONTROLLER_PACKET_TYPE_OFFSSET + 2] = (type >> 8) & 0xFF;
        self.buffer[CONTROLLER_PACKET_TYPE_OFFSSET + 3] = type & 0xFF;
    def get_packet_type(self):
        type = 0
        type = self.buffer[CONTROLLER_PACKET_TYPE_OFFSSET]
        type = (type << 8) | self.buffer[CONTROLLER_PACKET_TYPE_OFFSSET + 1];
        type = (type << 8) | self.buffer[CONTROLLER_PACKET_TYPE_OFFSSET + 2];
        type = (type << 8) | self.buffer[CONTROLLER_PACKET_TYPE_OFFSSET + 3];
        return type

    def set_packet_length(self, length):
        self.buffer[CONTROLLER_LENGTH_OFFSET] = (length >> 24) & 0xFF;
        self.buffer[CONTROLLER_LENGTH_OFFSET + 1] = (length >> 16) & 0xFF;
        self.buffer[CONTROLLER_LENGTH_OFFSET + 2] = (length >> 8) & 0xFF;
        self.buffer[CONTROLLER_LENGTH_OFFSET + 3] = length & 0xFF;
    def get_packet_length(self):
        length = 0
        length = self.buffer[CONTROLLER_LENGTH_OFFSET]
        length = (length << 8) | self.buffer[CONTROLLER_LENGTH_OFFSET + 1];
        length = (length << 8) | self.buffer[CONTROLLER_LENGTH_OFFSET + 2];
        length = (length << 8) | self.buffer[CONTROLLER_LENGTH_OFFSET + 3];
        return length

HEART_BEAT_TYPE = 1
HEART_BEAT_TYPE_OFFSSET = 0
HEART_BEAT_TYPE_LENGTH = 4
HEART_BEAT_LENGTH_OFFSET = 4
HEART_BEAT_LENGTH_LENGTH = 4
HEART_BEAT_HMAC_OFFSET = 8
HEART_BEAT_HMAC_LENGTH = 32
HEART_BEAT_NONCE_OFFSET = 40
HEART_BEAT_NONCE_LENGTH = 4
HEART_BEAT_HIT_OFFSET = 44
HEART_BEAT_HIT_LENGTH = 16
HEART_BEAT_IP_OFFSET = 60
HEART_BEAT_IP_LENGTH = 4
BASIC_HEADER_OFFSET = 44
HEART_BEAT_PACKET_LENGTH = 68
HEART_BEAT_HOST_NAME_LENGTH_OFFSET = 64
HEART_BEAT_HOST_NAME_LENGTH_LENGTH = 4
HEART_BEAT_HOST_NAME_OFFSET = 68

class HeartbeatPacket(ControllerPacket):
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = bytearray([0] * (HEART_BEAT_TYPE_LENGTH +
                                           HEART_BEAT_LENGTH_LENGTH +
                                           HEART_BEAT_HMAC_LENGTH +
                                           HEART_BEAT_NONCE_LENGTH +
                                           HEART_BEAT_HIT_LENGTH +
                                           HEART_BEAT_IP_LENGTH + 
                                           HEART_BEAT_HOST_NAME_LENGTH_LENGTH))
        else:
            self.buffer = buffer
    def set_packet_type(self, type):
        self.buffer[HEART_BEAT_TYPE_OFFSSET] = (type >> 24) & 0xFF;
        self.buffer[HEART_BEAT_TYPE_OFFSSET + 1] = (type >> 16) & 0xFF;
        self.buffer[HEART_BEAT_TYPE_OFFSSET + 2] = (type >> 8) & 0xFF;
        self.buffer[HEART_BEAT_TYPE_OFFSSET + 3] = type & 0xFF;
    def get_packet_type(self):
        type = 0
        type = self.buffer[HEART_BEAT_TYPE_OFFSSET]
        type = (type << 8) | self.buffer[HEART_BEAT_TYPE_OFFSSET + 1];
        type = (type << 8) | self.buffer[HEART_BEAT_TYPE_OFFSSET + 2];
        type = (type << 8) | self.buffer[HEART_BEAT_TYPE_OFFSSET + 3];
        return type
    def set_packet_length(self, length):
        self.buffer[HEART_BEAT_LENGTH_OFFSET] = (length >> 24) & 0xFF;
        self.buffer[HEART_BEAT_LENGTH_OFFSET + 1] = (length >> 16) & 0xFF;
        self.buffer[HEART_BEAT_LENGTH_OFFSET + 2] = (length >> 8) & 0xFF;
        self.buffer[HEART_BEAT_LENGTH_OFFSET + 3] = length & 0xFF;
    def get_packet_length(self):
        length = 0
        length = self.buffer[HEART_BEAT_LENGTH_OFFSET]
        length = (length << 8) | self.buffer[HEART_BEAT_LENGTH_OFFSET + 1];
        length = (length << 8) | self.buffer[HEART_BEAT_LENGTH_OFFSET + 2];
        length = (length << 8) | self.buffer[HEART_BEAT_LENGTH_OFFSET + 3];
        return length
    def set_hmac(self, hmac):
        self.buffer[HEART_BEAT_HMAC_OFFSET:HEART_BEAT_HMAC_OFFSET + HEART_BEAT_HMAC_LENGTH] = hmac
    def get_hmac(self):
        return self.buffer[HEART_BEAT_HMAC_OFFSET:HEART_BEAT_HMAC_OFFSET + HEART_BEAT_HMAC_LENGTH]
    def set_nonce(self, nonce):
        self.buffer[HEART_BEAT_NONCE_OFFSET:HEART_BEAT_NONCE_OFFSET + HEART_BEAT_NONCE_LENGTH] = nonce
    def get_nonce(self):
        return self.buffer[HEART_BEAT_NONCE_OFFSET:HEART_BEAT_NONCE_OFFSET + HEART_BEAT_NONCE_LENGTH]
    def set_hit(self, hit):
        self.buffer[HEART_BEAT_HIT_OFFSET:HEART_BEAT_HIT_OFFSET + HEART_BEAT_HIT_LENGTH] = hit
    def get_hit(self):
        return self.buffer[HEART_BEAT_HIT_OFFSET:HEART_BEAT_HIT_OFFSET + HEART_BEAT_HIT_LENGTH]
    def set_ip(self, ip):
        self.buffer[HEART_BEAT_IP_OFFSET:HEART_BEAT_IP_OFFSET + HEART_BEAT_IP_LENGTH] = ip
    def get_ip(self):
        return self.buffer[HEART_BEAT_IP_OFFSET:HEART_BEAT_IP_OFFSET + HEART_BEAT_IP_LENGTH]
    def set_hostname_length(self, length):
        self.buffer[HEART_BEAT_HOST_NAME_LENGTH_OFFSET] = (length >> 24) & 0xFF;
        self.buffer[HEART_BEAT_HOST_NAME_LENGTH_OFFSET + 1] = (length >> 16) & 0xFF;
        self.buffer[HEART_BEAT_HOST_NAME_LENGTH_OFFSET + 2] = (length >> 8) & 0xFF;
        self.buffer[HEART_BEAT_HOST_NAME_LENGTH_OFFSET + 3] = length & 0xFF;
    def get_hostname_length(self):
        length = 0
        length = self.buffer[HEART_BEAT_HOST_NAME_LENGTH_OFFSET]
        length = (length << 8) | self.buffer[HEART_BEAT_HOST_NAME_LENGTH_OFFSET + 1];
        length = (length << 8) | self.buffer[HEART_BEAT_HOST_NAME_LENGTH_OFFSET + 2];
        length = (length << 8) | self.buffer[HEART_BEAT_HOST_NAME_LENGTH_OFFSET + 3];
        return length
    def set_hostname(self, hostname, length):
        self.buffer[HEART_BEAT_HOST_NAME_OFFSET:HEART_BEAT_HOST_NAME_OFFSET + length] = hostname
    def get_hostname(self):
        length = self.get_hostname_length()
        return self.buffer[HEART_BEAT_HOST_NAME_OFFSET:HEART_BEAT_HOST_NAME_OFFSET + length]

    def get_buffer(self):
        return self.buffer;
    
FIREWALL_CONFIGURATION_TYPE = 2
FIREWALL_CONFIGURATION_TYPE_OFFSSET = 0
FIREWALL_CONFIGURATION_TYPE_LENGTH = 4
FIREWALL_CONFIGURATION_LENGTH_OFFSET = 4
FIREWALL_CONFIGURATION_LENGTH_LENGTH = 4
FIREWALL_CONFIGURATION_HMAC_OFFSET = 8
FIREWALL_CONFIGURATION_HMAC_LENGTH = 32
FIREWALL_CONFIGURATION_NONCE_OFFSET = 40
FIREWALL_CONFIGURATION_NONCE_LENGTH = 4
FIREWALL_CONFIGURATION_NUM_OFFSET = 44
FIREWALL_CONFIGURATION_NUM_LENGTH = 4
FIREWALL_CONFIGURATION_HIT_LENGTH = 16
FIREWALL_CONFIGURATION_RULE_LENGTH = 4

class FirewallConfigurationPacket(ControllerPacket):
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = bytearray([0] * (FIREWALL_CONFIGURATION_TYPE_LENGTH +
                                           FIREWALL_CONFIGURATION_LENGTH_LENGTH +
                                           FIREWALL_CONFIGURATION_HMAC_LENGTH +
                                           FIREWALL_CONFIGURATION_NONCE_LENGTH))
        else:
            self.buffer = buffer
    def set_packet_type(self, type):
        self.buffer[FIREWALL_CONFIGURATION_TYPE_OFFSSET] = (type >> 24) & 0xFF;
        self.buffer[FIREWALL_CONFIGURATION_TYPE_OFFSSET + 1] = (type >> 16) & 0xFF;
        self.buffer[FIREWALL_CONFIGURATION_TYPE_OFFSSET + 2] = (type >> 8) & 0xFF;
        self.buffer[FIREWALL_CONFIGURATION_TYPE_OFFSSET + 3] = type & 0xFF;
    def get_packet_type(self):
        type = 0
        type = self.buffer[FIREWALL_CONFIGURATION_TYPE_OFFSSET]
        type = (type << 8) | self.buffer[FIREWALL_CONFIGURATION_TYPE_OFFSSET + 1];
        type = (type << 8) | self.buffer[FIREWALL_CONFIGURATION_TYPE_OFFSSET + 2];
        type = (type << 8) | self.buffer[FIREWALL_CONFIGURATION_TYPE_OFFSSET + 3];
        return type
    def set_packet_length(self, length):
        self.buffer[FIREWALL_CONFIGURATION_LENGTH_OFFSET] = (length >> 24) & 0xFF;
        self.buffer[FIREWALL_CONFIGURATION_LENGTH_OFFSET + 1] = (length >> 16) & 0xFF;
        self.buffer[FIREWALL_CONFIGURATION_LENGTH_OFFSET + 2] = (length >> 8) & 0xFF;
        self.buffer[FIREWALL_CONFIGURATION_LENGTH_OFFSET + 3] = length & 0xFF;
    def get_packet_length(self):
        length = 0
        length = self.buffer[FIREWALL_CONFIGURATION_LENGTH_OFFSET]
        length = (length << 8) | self.buffer[FIREWALL_CONFIGURATION_LENGTH_OFFSET + 1];
        length = (length << 8) | self.buffer[FIREWALL_CONFIGURATION_LENGTH_OFFSET + 2];
        length = (length << 8) | self.buffer[FIREWALL_CONFIGURATION_LENGTH_OFFSET + 3];
        return length
    def set_hmac(self, hmac):
        self.buffer[FIREWALL_CONFIGURATION_HMAC_OFFSET:FIREWALL_CONFIGURATION_HMAC_OFFSET + FIREWALL_CONFIGURATION_HMAC_LENGTH] = hmac
    def get_hmac(self):
        return self.buffer[FIREWALL_CONFIGURATION_HMAC_OFFSET:FIREWALL_CONFIGURATION_HMAC_OFFSET + FIREWALL_CONFIGURATION_HMAC_LENGTH]
    def set_nonce(self, nonce):
        self.buffer[FIREWALL_CONFIGURATION_NONCE_OFFSET:FIREWALL_CONFIGURATION_NONCE_OFFSET + FIREWALL_CONFIGURATION_NONCE_LENGTH] = nonce
    def get_nonce(self):
        return self.buffer[FIREWALL_CONFIGURATION_NONCE_OFFSET:FIREWALL_CONFIGURATION_NONCE_OFFSET + FIREWALL_CONFIGURATION_NONCE_LENGTH]
    def get_rules(self):
        num = self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET] & 0xFF
        num = (num << 8) | (self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 1] & 0xFF)
        num = (num << 8) | (self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 2] & 0xFF)
        num = (num << 8) | (self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 3] & 0xFF)
        rules = []
        for i in range(0, num):
            hit1 = self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               (FIREWALL_CONFIGURATION_HIT_LENGTH * 2 * i) + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i:
                               FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 1) +
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i]
            hit2 = self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 1) + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i:
                               FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               (FIREWALL_CONFIGURATION_NUM_LENGTH + 
                                FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 2)) +
                                FIREWALL_CONFIGURATION_RULE_LENGTH * i]
            rule = (self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 2) +
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i] << 24) 
            rule = (self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i +
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 2) + 1] << 16) | rule
            rule = (self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i +
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 2) + 2] << 8) | rule
            rule = (self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i +
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 2) + 3]) | rule
            rules.append({
                "hit1": hit1,
                "hit2": hit2,
                "rule": rule
            })
        return rules
    
    def set_rules(self, rules, num):
        self.buffer += bytearray([0] * (HOSTS_CONFIGURATION_NUM_LENGTH + num * (FIREWALL_CONFIGURATION_HIT_LENGTH *2 + FIREWALL_CONFIGURATION_RULE_LENGTH)))
        self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET] = (num >> 24) & 0xFF
        self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 1] = (num >> 16) & 0xFF
        self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 2] = (num >> 8) & 0xFF
        self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 3] =  num & 0xFF
        for i in range(0, num):
            self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * 2 * i + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i:
                               FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 1) + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i] = bytearray(rules[i]["hit1"])
            self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 1) + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i:
                               FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 2) + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i] = bytearray(rules[i]["hit2"])
            self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 2) + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i] = (rules[i]["rule"] >> 24) & 0xFF 
            self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 2) +
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i + 1]  = (rules[i]["rule"]>> 16) & 0xFF
            self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 2) + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i + 2]  = (rules[i]["rule"]>> 8) & 0xFF
            self.buffer[FIREWALL_CONFIGURATION_NUM_OFFSET + 
                               FIREWALL_CONFIGURATION_NUM_LENGTH + 
                               FIREWALL_CONFIGURATION_HIT_LENGTH * (2 * i + 2) + 
                               FIREWALL_CONFIGURATION_RULE_LENGTH * i + 3]  = rules[i]["rule"] & 0xFF
    def get_buffer(self):
        return self.buffer;

HOSTS_CONFIGURATION_TYPE = 3
HOSTS_CONFIGURATION_TYPE_OFFSSET = 0
HOSTS_CONFIGURATION_TYPE_LENGTH = 4
HOSTS_CONFIGURATION_LENGTH_OFFSET = 4
HOSTS_CONFIGURATION_LENGTH_LENGTH = 4
HOSTS_CONFIGURATION_HMAC_OFFSET = 8
HOSTS_CONFIGURATION_HMAC_LENGTH = 32
HOSTS_CONFIGURATION_NONCE_OFFSET = 40
HOSTS_CONFIGURATION_NONCE_LENGTH = 4
HOSTS_CONFIGURATION_NUM_OFFSET = 44
HOSTS_CONFIGURATION_NUM_LENGTH = 4
HOSTS_CONFIGURATION_HIT_LENGTH = 16
HOSTS_CONFIGURATION_IP_LENGTH = 4

class HostsConfigurationPacket(ControllerPacket):
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = bytearray([0] * (HOSTS_CONFIGURATION_TYPE_LENGTH +
                                           HOSTS_CONFIGURATION_LENGTH_LENGTH +
                                           HOSTS_CONFIGURATION_HMAC_LENGTH +
                                           HOSTS_CONFIGURATION_NONCE_LENGTH))
        else:
            self.buffer = buffer
    def set_packet_type(self, type):
        self.buffer[HOSTS_CONFIGURATION_TYPE_OFFSSET] = (type >> 24) & 0xFF;
        self.buffer[HOSTS_CONFIGURATION_TYPE_OFFSSET + 1] = (type >> 16) & 0xFF;
        self.buffer[HOSTS_CONFIGURATION_TYPE_OFFSSET + 2] = (type >> 8) & 0xFF;
        self.buffer[HOSTS_CONFIGURATION_TYPE_OFFSSET + 3] = type & 0xFF;
    def get_packet_type(self):
        type = 0
        type = self.buffer[HOSTS_CONFIGURATION_TYPE_OFFSSET]
        type = (type << 8) | self.buffer[HOSTS_CONFIGURATION_TYPE_OFFSSET + 1];
        type = (type << 8) | self.buffer[HOSTS_CONFIGURATION_TYPE_OFFSSET + 2];
        type = (type << 8) | self.buffer[HOSTS_CONFIGURATION_TYPE_OFFSSET + 3];
        return type
    def set_packet_length(self, length):
        self.buffer[HOSTS_CONFIGURATION_LENGTH_OFFSET] = (length >> 24) & 0xFF;
        self.buffer[HOSTS_CONFIGURATION_LENGTH_OFFSET + 1] = (length >> 16) & 0xFF;
        self.buffer[HOSTS_CONFIGURATION_LENGTH_OFFSET + 2] = (length >> 8) & 0xFF;
        self.buffer[HOSTS_CONFIGURATION_LENGTH_OFFSET + 3] = length & 0xFF;
    def get_packet_length(self):
        length = 0
        length = self.buffer[HOSTS_CONFIGURATION_LENGTH_OFFSET]
        length = (length << 8) | self.buffer[HOSTS_CONFIGURATION_LENGTH_OFFSET + 1];
        length = (length << 8) | self.buffer[HOSTS_CONFIGURATION_LENGTH_OFFSET + 2];
        length = (length << 8) | self.buffer[HOSTS_CONFIGURATION_LENGTH_OFFSET + 3];
        return length
    def set_hmac(self, hmac):
        self.buffer[HOSTS_CONFIGURATION_HMAC_OFFSET:HOSTS_CONFIGURATION_HMAC_OFFSET + HOSTS_CONFIGURATION_HMAC_LENGTH] = hmac
    def get_hmac(self):
        return self.buffer[HOSTS_CONFIGURATION_HMAC_OFFSET:HOSTS_CONFIGURATION_HMAC_OFFSET + HOSTS_CONFIGURATION_HMAC_LENGTH]
    def set_nonce(self, nonce):
        self.buffer[HOSTS_CONFIGURATION_NONCE_OFFSET:HOSTS_CONFIGURATION_NONCE_OFFSET + HOSTS_CONFIGURATION_NONCE_LENGTH] = nonce
    def get_nonce(self):
        return self.buffer[HOSTS_CONFIGURATION_NONCE_OFFSET:HOSTS_CONFIGURATION_NONCE_OFFSET + HOSTS_CONFIGURATION_NONCE_LENGTH]
    def get_hosts(self):
        num = self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET] & 0xFF
        num = (num << 8) | (self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET + 1] & 0xFF)
        num = (num << 8) | (self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET + 2] & 0xFF)
        num = (num << 8) | (self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET + 3] & 0xFF)
        hosts = []
        for i in range(0, num):
            hit = self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET + 
                               HOSTS_CONFIGURATION_NUM_LENGTH + 
                               HOSTS_CONFIGURATION_HIT_LENGTH * i +
                               HOSTS_CONFIGURATION_IP_LENGTH * i:
                               HOSTS_CONFIGURATION_NUM_OFFSET + 
                               HOSTS_CONFIGURATION_NUM_LENGTH + 
                               HOSTS_CONFIGURATION_IP_LENGTH * i +
                               HOSTS_CONFIGURATION_HIT_LENGTH * (i + 1)]
            ip = self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET + 
                               HOSTS_CONFIGURATION_NUM_LENGTH +
                               HOSTS_CONFIGURATION_IP_LENGTH * i + 
                               HOSTS_CONFIGURATION_HIT_LENGTH * (i + 1):
                               HOSTS_CONFIGURATION_NUM_OFFSET + 
                               HOSTS_CONFIGURATION_NUM_LENGTH + 
                               HOSTS_CONFIGURATION_IP_LENGTH * (i + 1) +
                                HOSTS_CONFIGURATION_HIT_LENGTH * (i + 1)]
            
            hosts.append({
                "hit": hit,
                "ip": ip
            })
        return hosts
    
    def set_hosts(self, hosts, num):
        self.buffer += bytearray([0] * (HOSTS_CONFIGURATION_NUM_LENGTH + num * (HOSTS_CONFIGURATION_HIT_LENGTH + HOSTS_CONFIGURATION_IP_LENGTH)))
        logging.debug("----------------------------------------********** -------------------------------------------")
        logging.debug(len(self.buffer))
        self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET] = (num >> 24) & 0xFF
        self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET + 1] = (num >> 16) & 0xFF
        self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET + 2] = (num >> 8) & 0xFF
        self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET + 3] =  num & 0xFF
        for i in range(0, num):
            self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET + 
                               HOSTS_CONFIGURATION_NUM_LENGTH + 
                               (HOSTS_CONFIGURATION_HIT_LENGTH * i) +
                               (HOSTS_CONFIGURATION_IP_LENGTH * i):
                               HOSTS_CONFIGURATION_NUM_OFFSET + 
                               HOSTS_CONFIGURATION_NUM_LENGTH + 
                               HOSTS_CONFIGURATION_IP_LENGTH * i +
                               HOSTS_CONFIGURATION_HIT_LENGTH * (i + 1)] = bytearray(hosts[i]["hit"])
            self.buffer[HOSTS_CONFIGURATION_NUM_OFFSET + 
                               HOSTS_CONFIGURATION_NUM_LENGTH + 
                                HOSTS_CONFIGURATION_IP_LENGTH * i +
                               (HOSTS_CONFIGURATION_HIT_LENGTH * (i + 1)):
                               HOSTS_CONFIGURATION_NUM_OFFSET + 
                               HOSTS_CONFIGURATION_NUM_LENGTH + 
                                HOSTS_CONFIGURATION_IP_LENGTH * (i + 1) +
                               HOSTS_CONFIGURATION_HIT_LENGTH * (i + 1)] = bytearray(hosts[i]["ip"]) 
        logging.debug("----------------------------------------********** -------------------------------------------")
        logging.debug(len(self.buffer))   
    def get_buffer(self):
        return self.buffer;


MESH_CONFIGURATION_TYPE = 4
MESH_CONFIGURATION_TYPE_OFFSSET = 0
MESH_CONFIGURATION_TYPE_LENGTH = 4
MESH_CONFIGURATION_LENGTH_OFFSET = 4
MESH_CONFIGURATION_LENGTH_LENGTH = 4
MESH_CONFIGURATION_HMAC_OFFSET = 8
MESH_CONFIGURATION_HMAC_LENGTH = 32
MESH_CONFIGURATION_NONCE_OFFSET = 40
MESH_CONFIGURATION_NONCE_LENGTH = 4
MESH_CONFIGURATION_NUM_OFFSET = 44
MESH_CONFIGURATION_NUM_LENGTH = 4
MESH_CONFIGURATION_HIT_LENGTH = 16

class MeshConfigurationPacket(ControllerPacket):
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = bytearray([0] * (MESH_CONFIGURATION_TYPE_LENGTH +
                                           MESH_CONFIGURATION_LENGTH_LENGTH +
                                           MESH_CONFIGURATION_HMAC_LENGTH +
                                           MESH_CONFIGURATION_NONCE_LENGTH))
        else:
            self.buffer = buffer
    def set_packet_type(self, type):
        self.buffer[MESH_CONFIGURATION_TYPE_OFFSSET] = (type >> 24) & 0xFF;
        self.buffer[MESH_CONFIGURATION_TYPE_OFFSSET + 1] = (type >> 16) & 0xFF;
        self.buffer[MESH_CONFIGURATION_TYPE_OFFSSET + 2] = (type >> 8) & 0xFF;
        self.buffer[MESH_CONFIGURATION_TYPE_OFFSSET + 3] = type & 0xFF;
    def get_packet_type(self):
        type = 0
        type = self.buffer[MESH_CONFIGURATION_TYPE_OFFSSET]
        type = (type << 8) | self.buffer[MESH_CONFIGURATION_TYPE_OFFSSET + 1];
        type = (type << 8) | self.buffer[MESH_CONFIGURATION_TYPE_OFFSSET + 2];
        type = (type << 8) | self.buffer[MESH_CONFIGURATION_TYPE_OFFSSET + 3];
        return type
    def set_packet_length(self, length):
        self.buffer[MESH_CONFIGURATION_LENGTH_OFFSET] = (length >> 24) & 0xFF;
        self.buffer[MESH_CONFIGURATION_LENGTH_OFFSET + 1] = (length >> 16) & 0xFF;
        self.buffer[MESH_CONFIGURATION_LENGTH_OFFSET + 2] = (length >> 8) & 0xFF;
        self.buffer[MESH_CONFIGURATION_LENGTH_OFFSET + 3] = length & 0xFF;
    def get_packet_length(self):
        length = 0
        length = self.buffer[MESH_CONFIGURATION_LENGTH_OFFSET]
        length = (length << 8) | self.buffer[MESH_CONFIGURATION_LENGTH_OFFSET + 2];
        length = (length << 8) | self.buffer[MESH_CONFIGURATION_LENGTH_OFFSET + 1];
        length = (length << 8) | self.buffer[MESH_CONFIGURATION_LENGTH_OFFSET + 3];
        return length
    def set_hmac(self, hmac):
        self.buffer[MESH_CONFIGURATION_HMAC_OFFSET:MESH_CONFIGURATION_HMAC_OFFSET + MESH_CONFIGURATION_HMAC_LENGTH] = hmac
    def get_hmac(self):
        return self.buffer[MESH_CONFIGURATION_HMAC_OFFSET:MESH_CONFIGURATION_HMAC_OFFSET + MESH_CONFIGURATION_HMAC_LENGTH]
    def set_nonce(self, nonce):
        self.buffer[MESH_CONFIGURATION_NONCE_OFFSET:MESH_CONFIGURATION_NONCE_OFFSET + MESH_CONFIGURATION_NONCE_LENGTH] = nonce
    def get_nonce(self):
        return self.buffer[MESH_CONFIGURATION_NONCE_OFFSET:MESH_CONFIGURATION_NONCE_OFFSET + MESH_CONFIGURATION_NONCE_LENGTH]
    def get_mesh(self):
        
        num = (self.buffer[MESH_CONFIGURATION_NUM_OFFSET]) & 0xFF
        num = (num << 8) | (self.buffer[MESH_CONFIGURATION_NUM_OFFSET + 1] & 0xFF)
        num = (num << 8) | (self.buffer[MESH_CONFIGURATION_NUM_OFFSET + 2] & 0xFF)
        num = (num << 8) | (self.buffer[MESH_CONFIGURATION_NUM_OFFSET + 3] & 0xFF)
        mesh = []
        for i in range(0, num):
            hit1 = self.buffer[MESH_CONFIGURATION_NUM_OFFSET + 
                               MESH_CONFIGURATION_NUM_LENGTH + 
                               (MESH_CONFIGURATION_HIT_LENGTH * 2 * i):
                               MESH_CONFIGURATION_NUM_OFFSET + 
                               MESH_CONFIGURATION_NUM_LENGTH + 
                               MESH_CONFIGURATION_HIT_LENGTH * (2 * i + 1)]
            hit2 = self.buffer[MESH_CONFIGURATION_NUM_OFFSET + 
                               MESH_CONFIGURATION_NUM_LENGTH + 
                               MESH_CONFIGURATION_HIT_LENGTH * (2 * i + 1):
                               MESH_CONFIGURATION_NUM_OFFSET + 
                               (MESH_CONFIGURATION_NUM_LENGTH + 
                                MESH_CONFIGURATION_HIT_LENGTH * (2 * i + 2))]
            
            mesh.append({
                "hit1": hit1,
                "hit2": hit2
            })
        return mesh
    
    def set_mesh(self, mesh, num):
        self.buffer += bytearray([0] * (HOSTS_CONFIGURATION_NUM_LENGTH + num * MESH_CONFIGURATION_HIT_LENGTH * 2))
        self.buffer[MESH_CONFIGURATION_NUM_OFFSET] = (num >> 24) & 0xFF
        self.buffer[MESH_CONFIGURATION_NUM_OFFSET + 1] = (num >> 16) & 0xFF
        self.buffer[MESH_CONFIGURATION_NUM_OFFSET + 2] = (num >> 8) & 0xFF
        self.buffer[MESH_CONFIGURATION_NUM_OFFSET + 3] =  num & 0xFF
        for i in range(0, num):
            self.buffer[MESH_CONFIGURATION_NUM_OFFSET + 
                               MESH_CONFIGURATION_NUM_LENGTH + 
                               MESH_CONFIGURATION_HIT_LENGTH * 2 * i: 
                               MESH_CONFIGURATION_NUM_OFFSET + 
                               MESH_CONFIGURATION_NUM_LENGTH + 
                               MESH_CONFIGURATION_HIT_LENGTH * (2 * i + 1)] = bytearray(mesh[i]["hit1"])
            self.buffer[MESH_CONFIGURATION_NUM_OFFSET + 
                               MESH_CONFIGURATION_NUM_LENGTH + 
                               MESH_CONFIGURATION_HIT_LENGTH * (2 * i + 1):
                               MESH_CONFIGURATION_NUM_OFFSET + 
                               MESH_CONFIGURATION_NUM_LENGTH + 
                               MESH_CONFIGURATION_HIT_LENGTH * (2 * i + 2)] = bytearray(mesh[i]["hit2"])
            
    def get_buffer(self):
        return self.buffer;

ACL_CONFIGURATION_TYPE = 5
ACL_CONFIGURATION_TYPE_OFFSSET = 0
ACL_CONFIGURATION_TYPE_LENGTH = 4
ACL_CONFIGURATION_LENGTH_OFFSET = 4
ACL_CONFIGURATION_LENGTH_LENGTH = 4
ACL_CONFIGURATION_HMAC_OFFSET = 8
ACL_CONFIGURATION_HMAC_LENGTH = 32
ACL_CONFIGURATION_NONCE_OFFSET = 40
ACL_CONFIGURATION_NONCE_LENGTH = 4
ACL_CONFIGURATION_NUM_OFFSET = 44
ACL_CONFIGURATION_NUM_LENGTH = 4
ACL_CONFIGURATION_MAC_LENGTH = 6
ACL_CONFIGURATION_RULE_LENGTH = 4

class ACLConfigurationPacket(ControllerPacket):
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = bytearray([0] * (ACL_CONFIGURATION_TYPE_LENGTH +
                                           ACL_CONFIGURATION_LENGTH_LENGTH +
                                           ACL_CONFIGURATION_HMAC_LENGTH +
                                           ACL_CONFIGURATION_NONCE_LENGTH))
        else:
            self.buffer = buffer
    def set_packet_type(self, type):
        self.buffer[ACL_CONFIGURATION_TYPE_OFFSSET] = (type >> 24) & 0xFF;
        self.buffer[ACL_CONFIGURATION_TYPE_OFFSSET + 1] = (type >> 16) & 0xFF;
        self.buffer[ACL_CONFIGURATION_TYPE_OFFSSET + 2] = (type >> 8) & 0xFF;
        self.buffer[ACL_CONFIGURATION_TYPE_OFFSSET + 3] = type & 0xFF;
    def get_packet_type(self):
        type = 0
        type = self.buffer[ACL_CONFIGURATION_TYPE_OFFSSET]
        type = (type << 8) | self.buffer[ACL_CONFIGURATION_TYPE_OFFSSET + 1];
        type = (type << 8) | self.buffer[ACL_CONFIGURATION_TYPE_OFFSSET + 2];
        type = (type << 8) | self.buffer[ACL_CONFIGURATION_TYPE_OFFSSET + 3];
        return type
    def set_packet_length(self, length):
        self.buffer[ACL_CONFIGURATION_LENGTH_OFFSET] = (length >> 24) & 0xFF;
        self.buffer[ACL_CONFIGURATION_LENGTH_OFFSET + 1] = (length >> 16) & 0xFF;
        self.buffer[ACL_CONFIGURATION_LENGTH_OFFSET + 2] = (length >> 8) & 0xFF;
        self.buffer[ACL_CONFIGURATION_LENGTH_OFFSET + 3] = length & 0xFF;
    def get_packet_length(self):
        length = 0
        length = self.buffer[ACL_CONFIGURATION_LENGTH_OFFSET]
        length = (length << 8) | self.buffer[ACL_CONFIGURATION_LENGTH_OFFSET + 2];
        length = (length << 8) | self.buffer[ACL_CONFIGURATION_LENGTH_OFFSET + 1];
        length = (length << 8) | self.buffer[ACL_CONFIGURATION_LENGTH_OFFSET + 3];
        return length
    def set_hmac(self, hmac):
        self.buffer[ACL_CONFIGURATION_HMAC_OFFSET:ACL_CONFIGURATION_HMAC_OFFSET + ACL_CONFIGURATION_HMAC_LENGTH] = hmac
    def get_hmac(self):
        return self.buffer[ACL_CONFIGURATION_HMAC_OFFSET:ACL_CONFIGURATION_HMAC_OFFSET + ACL_CONFIGURATION_HMAC_LENGTH]
    def set_nonce(self, nonce):
        self.buffer[ACL_CONFIGURATION_NONCE_OFFSET:ACL_CONFIGURATION_NONCE_OFFSET + ACL_CONFIGURATION_NONCE_LENGTH] = nonce
    def get_nonce(self):
        return self.buffer[ACL_CONFIGURATION_NONCE_OFFSET:ACL_CONFIGURATION_NONCE_OFFSET + ACL_CONFIGURATION_NONCE_LENGTH]
    def get_rules(self):
        num = self.buffer[ACL_CONFIGURATION_NUM_OFFSET] & 0xFF
        num = (num << 8) | (self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 1] & 0xFF)
        num = (num << 8) | (self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 2] & 0xFF)
        num = (num << 8) | (self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 3] & 0xFF)
        rules = []
        for i in range(0, num):
            hit1 = self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               (ACL_CONFIGURATION_MAC_LENGTH * 2 * i) + 
                               ACL_CONFIGURATION_RULE_LENGTH * i:
                               ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 1) +
                               ACL_CONFIGURATION_RULE_LENGTH * i]
            hit2 = self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 1) + 
                               ACL_CONFIGURATION_RULE_LENGTH * i:
                               ACL_CONFIGURATION_NUM_OFFSET + 
                               (ACL_CONFIGURATION_NUM_LENGTH + 
                                ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 2)) +
                                ACL_CONFIGURATION_RULE_LENGTH * i]
            rule = (self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 2) +
                               ACL_CONFIGURATION_RULE_LENGTH * i] << 24) 
            rule = (self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_RULE_LENGTH * i +
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 2) + 1] << 16) | rule
            rule = (self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_RULE_LENGTH * i +
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 2) + 2] << 8) | rule
            rule = (self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_RULE_LENGTH * i +
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 2) + 3]) | rule
            rules.append({
                "mac1": hit1,
                "mac2": hit2,
                "rule": rule
            })
        return rules
    
    def set_rules(self, rules, num):
        self.buffer += bytearray([0] * (ACL_CONFIGURATION_NUM_LENGTH + num * (ACL_CONFIGURATION_MAC_LENGTH *2 + ACL_CONFIGURATION_RULE_LENGTH)))
        self.buffer[ACL_CONFIGURATION_NUM_OFFSET] = (num >> 24) & 0xFF
        self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 1] = (num >> 16) & 0xFF
        self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 2] = (num >> 8) & 0xFF
        self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 3] =  num & 0xFF
        for i in range(0, num):
            self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * 2 * i + 
                               ACL_CONFIGURATION_RULE_LENGTH * i:
                               ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 1) + 
                               ACL_CONFIGURATION_RULE_LENGTH * i] = bytearray(rules[i]["mac1"])
            self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 1) + 
                               ACL_CONFIGURATION_RULE_LENGTH * i:
                               ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 2) + 
                               ACL_CONFIGURATION_RULE_LENGTH * i] = bytearray(rules[i]["mac2"])
            self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 2) + 
                               ACL_CONFIGURATION_RULE_LENGTH * i] = (rules[i]["rule"] >> 24) & 0xFF 
            self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 2) +
                               ACL_CONFIGURATION_RULE_LENGTH * i + 1]  = (rules[i]["rule"]>> 16) & 0xFF
            self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 2) + 
                               ACL_CONFIGURATION_RULE_LENGTH * i + 2]  = (rules[i]["rule"]>> 8) & 0xFF
            self.buffer[ACL_CONFIGURATION_NUM_OFFSET + 
                               ACL_CONFIGURATION_NUM_LENGTH + 
                               ACL_CONFIGURATION_MAC_LENGTH * (2 * i + 2) + 
                               ACL_CONFIGURATION_RULE_LENGTH * i + 3]  = rules[i]["rule"] & 0xFF
    def get_buffer(self):
        return self.buffer;
