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

__author__ = "Dmitriy Kuptsov"
__copyright__ = "Copyright 2020, strangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@gmail.com"
__status__ = "development"

from binascii import hexlify
# Import the needed libraries
# Stacktrace
import traceback
# Sockets
import socket
# Threading
import threading
# Logging
import logging
# Timing
import time
# Math functions
from math import ceil, floor
# System
import sys
# Exit handler
import atexit
# HIP related packets
from hiplib.packets import HIP
# IPSec packets
from hiplib.packets import IPSec
# IPv6 packets
from hiplib.packets import IPv6
# IPv4 packets 
from hiplib.packets import IPv4
# Configuration
from hiplib.config import config
# HIT
from hiplib.utils.hit import HIT
from hiplib.utils.hi import RSAHostID, ECDSAHostID, ECDSALowHostID
from hiplib.utils.di import DIFactory
# Utilities
from hiplib.utils.misc import Utils, Math
# Puzzle solver
from hiplib.utils.puzzles import PuzzleSolver
# Crypto
from hiplib.crypto import factory
from hiplib.crypto.asymmetric import RSAPublicKey, RSAPrivateKey, ECDSAPublicKey, ECDSAPrivateKey, RSASHA256Signature, ECDSALowPublicKey, ECDSALowPrivateKey, ECDSASHA384Signature, ECDSASHA1Signature
from hiplib.crypto.factory import HMACFactory, SymmetricCiphersFactory, ESPTransformFactory
# Tun interface
from hiplib.network import tun
# Routing
from hiplib.network import routing
# States
from hiplib.databases import HIPState
from hiplib.databases import SA
from hiplib.databases import resolver
from hiplib.databases import Firewall
# Utilities
from hiplib.utils.misc import Utils

class HIPLib():
    def __init__(self, config):
        self.config = config;
        self.MTU = self.config["network"]["mtu"];

        self.firewall = Firewall.BasicFirewall();
        self.firewall.load_rules(self.config["firewall"]["rules_file"])

        # HIP v2 https://tools.ietf.org/html/rfc7401#section-3
        # Configure resolver
        logging.info("Using hosts file to resolve HITS %s" % (self.config["resolver"]["hosts_file"]));
        self.hit_resolver = resolver.HostsFileResolver(filename = self.config["resolver"]["hosts_file"]);

        # Security association database
        self.ip_sec_sa = SA.SecurityAssociationDatabase();
        # Domain identifier
        self.di = DIFactory.get(self.config["resolver"]["domain_identifier"]["type"], 
            bytearray(self.config["resolver"]["domain_identifier"]["value"], encoding="ascii"));

        #logging.debug(di);
        logging.info("Loading public key and constructing HIT")
        self.pubkey       = None;
        self.privkey      = None;
        self.hi           = None;
        self.ipv6_address = None;
        self.own_hit      = None;
        self.own_hi_param = None;
        if self.config["security"]["sig_alg"] == 0x5: # RSA
            if self.config["security"]["hash_alg"] != 0x1: # SHA 256
                raise Exception("Invalid hash algorithm. Must be 0x1")
            self.pubkey = RSAPublicKey.load_pem(self.config["security"]["public_key"]);
            self.privkey = RSAPrivateKey.load_pem(self.config["security"]["private_key"]);
            self.hi = RSAHostID(self.pubkey.get_public_exponent(), self.pubkey.get_modulus());
            self.ipv6_address = HIT.get_hex_formated(self.hi.to_byte_array(), HIT.SHA256_OGA);
            self.own_hit = HIT.get(self.hi.to_byte_array(), HIT.SHA256_OGA);
        elif self.config["security"]["sig_alg"] == 0x7: # ECDSA
            if self.config["security"]["hash_alg"] != 0x2: # SHA 384
                raise Exception("Invalid hash algorithm. Must be 0x2")
            self.pubkey = ECDSAPublicKey.load_pem(self.config["security"]["public_key"]);
            self.privkey = ECDSAPrivateKey.load_pem(self.config["security"]["private_key"]);
            logging.debug(self.pubkey.get_key_info());
            self.hi = ECDSAHostID(self.pubkey.get_curve_id(), self.pubkey.get_x(), self.pubkey.get_y());
            self.ipv6_address = HIT.get_hex_formated(self.hi.to_byte_array(), HIT.SHA384_OGA);
            logging.debug(list(self.hi.to_byte_array()));
            own_hit = HIT.get(self.hi.to_byte_array(), HIT.SHA384_OGA);
            logging.debug("Responder's OGA ID %d" % (HIT.SHA384_OGA));
            logging.debug(list(self.hi.to_byte_array()));
            logging.debug(list(own_hit))
        elif self.config["security"]["sig_alg"] == 0x9: # ECDSA LOW
            if self.config["security"]["hash_alg"] != 0x3: # SHA 1
                raise Exception("Invalid hash algorithm. Must be 0x3")
            self.pubkey = ECDSALowPublicKey.load_pem(self.config["security"]["public_key"]);
            self.privkey = ECDSALowPrivateKey.load_pem(self.config["security"]["private_key"]);
            self.hi = ECDSALowHostID(self.pubkey.get_curve_id(), self.pubkey.get_x(), self.pubkey.get_y());
            self.ipv6_address = HIT.get_hex_formated(self.hi.to_byte_array(), HIT.SHA1_OGA);
            self.own_hit = HIT.get(self.hi.to_byte_array(), HIT.SHA1_OGA);
        else:
            raise Exception("Unsupported Host ID algorithm")
        self.hip_state_machine = HIPState.StateMachine();
        self.keymat_storage    = HIPState.Storage();
        self.dh_storage        = {}
        self.dh_storage_I2     = HIPState.Storage();
        self.dh_storage_R1     = HIPState.Storage();
        self.j_storage         = HIPState.Storage();
        self.i_storage         = HIPState.Storage();
        self.cipher_storage    = HIPState.Storage();
        self.pubkey_storage    = HIPState.Storage();
        self.state_variables   = HIPState.Storage();
        self.key_info_storage  = HIPState.Storage();
        self.esp_transform_storage = HIPState.Storage();
        self.hi_param_storage  = HIPState.Storage();

        if self.config["general"]["rekey_after_packets"] > ((2<<32)-1):
            self.config["general"]["rekey_after_packets"] = (2<<32)-1;

    def get_own_hit(self):
        return self.own_hit;

    def reload_config(self):
        self.firewall.load_rules(self.config["firewall"]["rules_file"])
        logging.info("Using hosts file to resolve HITS %s" % (self.config["resolver"]["hosts_file"]));
        self.hit_resolver.load_records(filename = self.config["resolver"]["hosts_file"]);
        
    def process_hip_packet(self, packet):
        try:
            response = [];
            # IP reassmebly is done automatically so we can read large enough packets
            #buf = bytearray(hip_socket.recv(4*MTU));
            ipv4_packet = IPv4.IPv4Packet(packet);

            src = ipv4_packet.get_source_address();
            dst = ipv4_packet.get_destination_address();

            dst_str = Utils.ipv4_bytes_to_string(dst);
            src_str = Utils.ipv4_bytes_to_string(src);

            if ipv4_packet.get_protocol() != HIP.HIP_PROTOCOL:
                logging.debug("Invalid protocol type");
                return [];

            if len(ipv4_packet.get_payload()) % 8:
                logging.debug("Invalid length of the payload. Must be multiple of 8 bytes");
                return [];

            hip_packet = HIP.HIPPacket(ipv4_packet.get_payload());

            ihit = hip_packet.get_senders_hit();
            rhit = hip_packet.get_receivers_hit();

            if not self.firewall.allow(Utils.ipv6_bytes_to_hex_formatted_resolver(ihit), Utils.ipv6_bytes_to_hex_formatted_resolver(rhit)):
                logging.critical("Blocked by firewall...")
                return [];
        
            if Utils.is_hit_smaller(rhit, ihit):
                hip_state = self.hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                    Utils.ipv6_bytes_to_hex_formatted(ihit));
            else:
                hip_state = self.hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(rhit));

            if hip_packet.get_version() != HIP.HIP_VERSION:
                logging.critical("Only HIP version 2 is supported");
                return [];

            # Check wether the destination address is our own HIT
            if not Utils.hits_equal(rhit, self.own_hit) and not Utils.hits_equal(rhit, [0] * 16):
                logging.critical("Not our HIT");
                logging.critical(Utils.ipv6_bytes_to_hex_formatted(rhit));
                logging.critical(Utils.ipv6_bytes_to_hex_formatted(self.own_hit));
                return [];

            # https://tools.ietf.org/html/rfc7401#section-5
            original_checksum = hip_packet.get_checksum();
            hip_packet.set_checksum(0x0);
            # Verify checksum
            checksum = Utils.hip_ipv4_checksum(
                src, 
                dst, 
                HIP.HIP_PROTOCOL, 
                hip_packet.get_length() * 8 + 8, 
                hip_packet.get_buffer());
            
            if original_checksum != checksum:
                logging.critical("Invalid checksum");
                return [];

            if hip_packet.get_packet_type() == HIP.HIP_I1_PACKET:
                logging.info("I1 packet");

                if hip_state.is_i1_sent() and Utils.is_hit_smaller(rhit, ihit):
                    logging.debug("Staying in I1-SENT state");
                    return [];

                sv = None
                
                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                            Utils.ipv6_bytes_to_hex_formatted(ihit))
                    
                    if not sv:
                        sv = HIPState.StateVariables(hip_state.get_state(), ihit, rhit, dst, src)
                     
                        self.state_variables.save(Utils.ipv6_bytes_to_hex_formatted(rhit),
                            Utils.ipv6_bytes_to_hex_formatted(ihit),
                            sv)
                        sv.is_responder = True;
                        sv.ihit = ihit;
                        sv.rhit = rhit;
                    else:
                        sv.state = hip_state.get_state()
                        sv.is_responder = True;
                        sv.ihit = ihit;
                        sv.rhit = rhit;
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                            Utils.ipv6_bytes_to_hex_formatted(rhit))
                            
                    if not sv:
                        sv = HIPState.StateVariables(hip_state.get_state(), ihit, rhit, dst, src)
                        self.state_variables.save(Utils.ipv6_bytes_to_hex_formatted(ihit),
                            Utils.ipv6_bytes_to_hex_formatted(rhit),
                            sv)
                        sv.is_responder = True;
                        sv.ihit = ihit;
                        sv.rhit = rhit;
                    else:
                        sv.state = hip_state.get_state()
                        sv.is_responder = True;
                        sv.ihit = ihit;
                        sv.rhit = rhit;

                # Check the state of the HIP protocol
                # R1 packet should be constructed only 
                # if the state is not associated
                # Need to check with the RFC

                # Construct R1 packet
                hip_r1_packet = HIP.R1Packet();
                hip_r1_packet.set_senders_hit(rhit);
                #hip_r1_packet.set_receivers_hit(ihit);
                hip_r1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_r1_packet.set_version(HIP.HIP_VERSION);

                r_hash = HIT.get_responders_hash_algorithm(rhit);

                # R1 Counter 
                r1counter_param = HIP.R1CounterParameter()
                sv.r1_counter += 1
                r1counter_param.set_counter(sv.r1_counter)

                # Prepare puzzle
                irandom = PuzzleSolver.generate_irandom(r_hash.LENGTH);
                puzzle_param = HIP.PuzzleParameter(buffer = None, rhash_length = r_hash.LENGTH);
                puzzle_param.set_k_value(self.config["security"]["puzzle_difficulty"]);
                puzzle_param.set_lifetime(self.config["security"]["puzzle_lifetime_exponent"]);
                puzzle_param.set_random([0] * r_hash.LENGTH, rhash_length = r_hash.LENGTH);
                puzzle_param.set_opaque(bytearray([0, 0]));
                
                # HIP DH groups parameter
                dh_groups_param = HIP.DHGroupListParameter();
                # Prepare Diffie-Hellman parameters
                dh_groups_param_initiator = None;
                parameters = hip_packet.get_parameters();
                for parameter in parameters:
                    if isinstance(parameter, HIP.DHGroupListParameter):
                        dh_groups_param_initiator = parameter;
                if not dh_groups_param_initiator:
                    # Drop HIP BEX?
                    logging.debug("No DH groups parameter found. Dropping I1 packet");
                    return [];
                offered_dh_groups = dh_groups_param_initiator.get_groups();
                supported_dh_groups = self.config["security"]["supported_DH_groups"];
                selected_dh_group = None;
                for group in offered_dh_groups:
                    if group in supported_dh_groups:
                        dh_groups_param.add_groups([group]);
                        selected_dh_group = group;
                        break;
                if not selected_dh_group:
                    logging.debug("Unsupported DH group");
                    return [];

                dh = factory.DHFactory.get(selected_dh_group);
                private_key = dh.generate_private_key();
                public_key = dh.generate_public_key();

                if not self.dh_storage.get(r1counter_param.get_counter(), None):
                    self.dh_storage[r1counter_param.get_counter()] = HIPState.Storage()
                 
                self.dh_storage[r1counter_param.get_counter()].save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(rhit), dh);
                

                dh_param = HIP.DHParameter();
                dh_param.set_group_id(selected_dh_group);
                dh_param.add_public_value(dh.encode_public_key());

                # HIP cipher parameter
                cipher_param = HIP.CipherParameter();
                cipher_param.add_ciphers(self.config["security"]["supported_ciphers"]);

                # ESP transform parameter
                esp_transform_param = HIP.ESPTransformParameter();
                esp_transform_param.add_suits(self.config["security"]["supported_esp_transform_suits"]);

                # HIP host ID parameter
                hi_param = HIP.HostIdParameter();
                hi_param.set_host_id(self.hi);
                # It is important to set domain ID after host ID was set
                logging.debug(self.di);
                hi_param.set_domain_id(self.di);

                self.own_hi_param = hi_param;

                # HIP HIT suit list parameter
                hit_suit_param = HIP.HITSuitListParameter();
                hit_suit_param.add_suits(self.config["security"]["supported_hit_suits"]);

                # Transport format list
                transport_param = HIP.TransportListParameter();
                transport_param.add_transport_formats(self.config["security"]["supported_transports"]);

                # HIP signature parameter
                signature_param = HIP.Signature2Parameter();

                # Compute signature here
                buf = r1counter_param.get_byte_buffer() + \
                        puzzle_param.get_byte_buffer() + \
                        dh_param.get_byte_buffer() + \
                        cipher_param.get_byte_buffer() + \
                        esp_transform_param.get_byte_buffer() + \
                        hi_param.get_byte_buffer() + \
                        hit_suit_param.get_byte_buffer() + \
                        dh_groups_param.get_byte_buffer() + \
                        transport_param.get_byte_buffer();
                original_length = hip_r1_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_r1_packet.set_length(int(packet_length / 8));
                buf = hip_r1_packet.get_buffer() + buf;

                if isinstance(self.privkey, RSAPrivateKey):
                    signature_alg = RSASHA256Signature(self.privkey.get_key_info());
                elif isinstance(self.privkey, ECDSAPrivateKey):
                    signature_alg = ECDSASHA384Signature(self.privkey.get_key_info());
                elif isinstance(self.privkey, ECDSALowPrivateKey):
                    signature_alg = ECDSASHA1Signature(self.privkey.get_key_info());

                #logging.debug(privkey.get_key_info());
                signature = signature_alg.sign(bytearray(buf));
                signature_param.set_signature_algorithm(self.config["security"]["sig_alg"]);
                signature_param.set_signature(signature);				

                # Add parameters to R1 packet (order is important)
                hip_r1_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);
                # List of mandatory parameters in R1 packet...
                
                puzzle_param.set_random(irandom, r_hash.LENGTH);
                puzzle_param.set_opaque(bytearray(Utils.generate_random(2)));
                hip_r1_packet.add_parameter(r1counter_param);
                hip_r1_packet.add_parameter(puzzle_param);
                hip_r1_packet.add_parameter(dh_param);
                hip_r1_packet.add_parameter(cipher_param);
                hip_r1_packet.add_parameter(esp_transform_param);
                hip_r1_packet.add_parameter(hi_param);
                hip_r1_packet.add_parameter(hit_suit_param);
                hip_r1_packet.add_parameter(dh_groups_param);
                hip_r1_packet.add_parameter(transport_param);
                hip_r1_packet.add_parameter(signature_param);

                # Swap the addresses
                temp = src;
                src = dst;
                dst = temp;

                # Set receiver's HIT
                hip_r1_packet.set_receivers_hit(ihit);

                # Create IPv4 packet
                ipv4_packet = IPv4.IPv4Packet();
                ipv4_packet.set_version(IPv4.IPV4_VERSION);
                ipv4_packet.set_destination_address(dst);
                ipv4_packet.set_source_address(src);
                ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
                ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

                # Calculate the checksum
                checksum = Utils.hip_ipv4_checksum(
                    src, 
                    dst, 
                    HIP.HIP_PROTOCOL, 
                    hip_r1_packet.get_length() * 8 + 8, 
                    hip_r1_packet.get_buffer());
                hip_r1_packet.set_checksum(checksum);
                ipv4_packet.set_payload(hip_r1_packet.get_buffer());
                # Send the packet
                dst_str = Utils.ipv4_bytes_to_string(dst);
                response.append((bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0)))
                # Stay in current state
            elif hip_packet.get_packet_type() == HIP.HIP_R1_PACKET:
                logging.info("----------------------------- R1 packet ----------------------------- ");
                
                # 1 0 1
                # 1 1 1
                if (hip_state.is_unassociated() 
                    or hip_state.is_r2_sent() 
                    or hip_state.is_established()
                    or hip_state.is_failed()):
                    logging.debug("Dropping packet... Invalid state");
                    return [];

                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                            Utils.ipv6_bytes_to_hex_formatted(ihit))
                    
                    if not sv:
                        sv = HIPState.StateVariables(hip_state.get_state(), rhit, ihit, dst, src)
                     
                        self.state_variables.save(Utils.ipv6_bytes_to_hex_formatted(rhit),
                            Utils.ipv6_bytes_to_hex_formatted(ihit),
                            sv)
                        sv.is_responder = False;
                        sv.ihit = rhit;
                        sv.rhit = ihit;
                    else:
                        sv.state = hip_state.get_state()
                        sv.is_responder = False;
                        sv.ihit = rhit;
                        sv.rhit = ihit;
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                            Utils.ipv6_bytes_to_hex_formatted(rhit))
                            
                    if not sv:
                        sv = HIPState.StateVariables(hip_state.get_state(), rhit, ihit, dst, src)
                        self.state_variables.save(Utils.ipv6_bytes_to_hex_formatted(ihit),
                            Utils.ipv6_bytes_to_hex_formatted(rhit),
                            sv)
                        sv.is_responder = False;
                        sv.ihit = rhit;
                        sv.rhit = ihit;
                    else:
                        sv.state = hip_state.get_state()
                        sv.is_responder = False;
                        sv.ihit = rhit;
                        sv.rhit = ihit;
                oga = HIT.get_responders_oga_id(ihit);
                

                if (oga << 4) not in self.config["security"]["supported_hit_suits"]:
                    logging.critical("Unsupported HIT suit");
                    logging.critical("OGA %d"  % (oga));
                    logging.critical(self.config["security"]["supported_hit_suits"]);
                    # Send I1
                    return [];

                puzzle_param       = None;
                r1_counter_param   = None;
                irandom            = None;
                opaque             = None;
                esp_tranform_param = None;
                dh_param           = None;
                cipher_param       = None;
                hi_param           = None;
                hit_suit_param     = None;
                dh_groups_param    = None;
                transport_param    = None;
                echo_signed        = None;
                signature_param    = None;
                public_key         = None;
                echo_unsigned      = [];
                parameters         = hip_packet.get_parameters();
                
                st = time.time();

                hip_r1_packet = HIP.R1Packet();
                hip_r1_packet.set_senders_hit(hip_packet.get_senders_hit());
                hip_r1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_r1_packet.set_version(HIP.HIP_VERSION);

                r_hash = HIT.get_responders_hash_algorithm(ihit);
                logging.debug(r_hash);
                logging.debug(parameters)
                logging.debug("!!!!!!!!!!!!!!!!!!!!!!")

                for parameter in parameters:
                    if isinstance(parameter, HIP.DHGroupListParameter):
                        logging.debug("DH groups parameter");
                        dh_groups_param = parameter;
                    if isinstance(parameter, HIP.R1CounterParameter):
                        logging.debug("R1 counter");
                        r1_counter_param = parameter;
                    if isinstance(parameter, HIP.PuzzleParameter):
                        logging.debug("Puzzle parameter");
                        puzzle_param = parameter;
                        irandom = puzzle_param.get_random(rhash_length = r_hash.LENGTH);
                        opaque = puzzle_param.get_opaque();
                        puzzle_param.set_random([0] * r_hash.LENGTH, r_hash.LENGTH);
                        puzzle_param.set_opaque(bytearray([0, 0]));
                    if isinstance(parameter, HIP.DHParameter):	
                        logging.debug("DH parameter");
                        dh_param = parameter;
                    if isinstance(parameter, HIP.HostIdParameter):
                        logging.debug("DI type: %d " % parameter.get_di_type());
                        logging.debug("DI value: %s " % parameter.get_domain_id());
                        logging.debug("Host ID");
                        hi_param = parameter;
                        # Check the algorithm and construct the HI based on the proposed algorithm
                        if hi_param.get_algorithm() == 0x5: #RSA
                            responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
                            repsonder_hit_calculated = HIT.get(responder_hi.to_byte_array(), HIT.SHA256_OGA)
                        elif hi_param.get_algorithm() == 0x7: #ECDSA
                            responder_hi = ECDSAHostID.from_byte_buffer(hi_param.get_host_id());
                            repsonder_hit_calculated = HIT.get(responder_hi.to_byte_array(), HIT.SHA384_OGA)
                        elif hi_param.get_algorithm() == 0x9: #ECDSA LOW
                            responder_hi = ECDSALowHostID.from_byte_buffer(hi_param.get_host_id());
                            repsonder_hit_calculated = HIT.get(responder_hi.to_byte_array(), HIT.SHA1_OGA)
                        else:
                            raise Exception("Invalid signature algorithm");
                        
                        # Calculate to make firewall verification secure...
                        if ihit != repsonder_hit_calculated:
                            raise Exception("Invalid source HIT")
                        if rhit != self.own_hit:
                            raise Exception("Invalid destination HIT")
                            
                        oga = HIT.get_responders_oga_id(ihit);
                        logging.debug("Responder's OGA ID %d" % (oga));
                        logging.debug(bytearray(responder_hi.to_byte_array()));
                        responders_hit = HIT.get(responder_hi.to_byte_array(), oga);
                        logging.debug(list(responders_hit))
                        logging.debug(list(ihit))
                        logging.debug(list(self.own_hit))
                        if not Utils.hits_equal(ihit, responders_hit):
                            logging.critical("Invalid HIT");
                            raise Exception("Invalid HIT");
                        
                        if isinstance(responder_hi, RSAHostID): #RSA
                            responders_public_key = RSAPublicKey.load_from_params(
                                responder_hi.get_exponent(), 
                                responder_hi.get_modulus());
                        elif isinstance(responder_hi, ECDSAHostID): #ECDSA
                            responders_public_key = ECDSAPublicKey.load_from_params(
                                responder_hi.get_curve_id(), 
                                responder_hi.get_x(),
                                responder_hi.get_y());
                        elif isinstance(responder_hi, ECDSALowHostID): #ECDSA LOW
                            responders_public_key = ECDSALowPublicKey.load_from_params(
                                responder_hi.get_curve_id(), 
                                responder_hi.get_x(),
                                responder_hi.get_y());
                        else:
                            raise Exception("Invalid signature algorithm");
                        
                        self.pubkey_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                            Utils.ipv6_bytes_to_hex_formatted(rhit), 
                            responders_public_key);
                    if isinstance(parameter, HIP.HITSuitListParameter):
                        logging.debug("HIT suit list");
                        hit_suit_param = parameter;
                    if isinstance(parameter, HIP.TransportListParameter):
                        logging.debug("Transport parameter");
                        logging.debug(parameter.get_transport_formats());
                        transport_param = parameter;
                    if isinstance(parameter, HIP.Signature2Parameter):
                        logging.debug("Signature parameter");
                        signature_param = parameter;
                    if isinstance(parameter, HIP.EchoRequestSignedParameter):
                        logging.debug("Echo request signed parameter");
                        echo_signed = HIP.EchoResponseSignedParameter();
                        echo_signed.add_opaque_data(parameter.get_opaque_data());
                    if isinstance(parameter, HIP.EchoRequestUnsignedParameter):
                        logging.debug("Echo request unsigned parameter");
                        echo_unsigned_param = HIP.EchoResponseUnsignedParameter();
                        echo_unsigned_param.add_opaque_data(parameter.get_opaque_data());
                        echo_unsigned.append(echo_unsigned_param);
                    if isinstance(parameter, HIP.CipherParameter):
                        logging.debug("Ciphers");
                        cipher_param = parameter;
                    if isinstance(parameter, HIP.ESPTransformParameter):
                        logging.debug("ESP transform");
                        esp_tranform_param = parameter;

                if not puzzle_param:
                    logging.critical("Missing puzzle parameter");
                    return [];
                if not dh_param:
                    logging.critical("Missing DH parameter");
                    return [];
                if not cipher_param:
                    logging.critical("Missing cipher parameter");
                    return [];
                if not esp_tranform_param:
                    logging.critical("Missing ESP transform parameter");
                    return [];
                if not hi_param:
                    logging.critical("Missing HI parameter");
                    return [];
                if not hit_suit_param:
                    logging.critical("Missing HIT suit parameter");
                    return [];
                if not dh_groups_param:
                    logging.critical("Missing DH groups parameter");
                    return [];
                if not transport_param:
                    logging.critical("Missing transport parameter");
                    return [];
                if not signature_param:
                    logging.critical("Missing signature parameter");
                    return [];
                if not dh_param.get_group_id() in dh_groups_param.get_groups():
                    logging.critical("Manipulation of DH group");
                    # Change the state to unassociated... drop the BEX
                    return [];
                
                start_time = time.time();
                jrandom = PuzzleSolver.solve_puzzle(irandom, hip_packet.get_receivers_hit(), hip_packet.get_senders_hit(), puzzle_param.get_k_value(), r_hash)
                logging.debug("Puzzle was solved and verified....");
                end_time = time.time();
                if (end_time - start_time) > (2 << (puzzle_param.get_lifetime() - 32)):
                    logging.critical("Maximum time to solve the puzzle exceeded. Dropping the packet...");
                    # Abandon the BEX
                    hip_state.unassociated();
                    return [];

                buf = bytearray([]);

                if r1_counter_param:
                    buf += r1_counter_param.get_byte_buffer();

                if not echo_signed:
                    buf += puzzle_param.get_byte_buffer() + \
                        dh_param.get_byte_buffer() + \
                        cipher_param.get_byte_buffer() + \
                        esp_tranform_param.get_byte_buffer() + \
                        hi_param.get_byte_buffer() + \
                        hit_suit_param.get_byte_buffer() + \
                        dh_groups_param.get_byte_buffer() + \
                        transport_param.get_byte_buffer();
                else:
                    buf += puzzle_param.get_byte_buffer() + \
                        dh_param.get_byte_buffer() + \
                        cipher_param.get_byte_buffer() + \
                        esp_tranform_param.get_byte_buffer() + \
                        hi_param.get_byte_buffer() + \
                        hit_suit_param.get_byte_buffer() + \
                        dh_groups_param.get_byte_buffer() + \
                        echo_signed.get_byte_buffer() + \
                        transport_param.get_byte_buffer();
                original_length = hip_r1_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_r1_packet.set_length(int(packet_length / 8));
                buf = bytearray(hip_r1_packet.get_buffer()) + bytearray(buf);
                if isinstance(responders_public_key, RSAPublicKey):
                    signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSAPublicKey):
                    signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
                    logging.debug(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSALowPublicKey):
                    signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());

                #logging.debug(privkey.get_key_info());

                if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
                    logging.critical("Invalid signature in R1 packet. Dropping the packet");
                    return [];
                
                logging.debug("DH public key value: %d ", Math.bytes_to_int(dh_param.get_public_value()));

                offered_dh_groups = dh_groups_param.get_groups();
                supported_dh_groups = self.config["security"]["supported_DH_groups"];
                selected_dh_group = None;
                for group in supported_dh_groups:
                    if group in offered_dh_groups:
                        selected_dh_group = group;
                        break;
                if not selected_dh_group:
                    logging.critical("Unsupported DH group");
                    # Transition to unassociated state
                    raise Exception("Unsupported DH group");

                dh = factory.DHFactory.get(selected_dh_group);
                private_key  = dh.generate_private_key();
                public_key_i = dh.generate_public_key();
                public_key_r = dh.decode_public_key(dh_param.get_public_value());
                shared_secret = dh.compute_shared_secret(public_key_r);
                if not self.dh_storage.get(r1_counter_param.get_counter(), None):
                    self.dh_storage[r1_counter_param.get_counter()] = HIPState.Storage()
                self.dh_storage[r1_counter_param.get_counter()].save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(rhit), dh);

                info = Utils.sort_hits(ihit, rhit);
                salt = irandom + jrandom;
                hmac_alg  = HIT.get_responders_oga_id(ihit);

                key_info = HIPState.KeyInfo(info, salt, dh.ALG_ID);

                if Utils.is_hit_smaller(rhit, ihit):
                    self.hi_param_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit), hi_param);
                    self.key_info_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit), key_info);
                else:
                    self.hi_param_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit), hi_param);
                    self.key_info_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit), key_info);

                offered_ciphers = cipher_param.get_ciphers();
                supported_ciphers = self.config["security"]["supported_ciphers"];
                selected_cipher = None;

                for cipher in offered_ciphers:
                    if cipher in supported_ciphers:
                        selected_cipher = cipher;
                        break;

                if not selected_cipher:
                    logging.critical("Unsupported cipher");
                    # Transition to unassociated state
                    raise Exception("Unsupported cipher");

                offered_esp_transforms = esp_tranform_param.get_suits();
                supported_esp_transform_suits = self.config["security"]["supported_esp_transform_suits"];
                selected_esp_transform = None;
                for suit in offered_esp_transforms:
                    if suit in supported_esp_transform_suits:
                        selected_esp_transform = suit;
                        break;

                if not selected_esp_transform:
                    logging.critical("Unsupported ESP transform suit");
                    raise Exception("Unsupported ESP transform suit");

                if Utils.is_hit_smaller(rhit, ihit):
                    self.esp_transform_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit), [selected_esp_transform]);
                else:
                    self.esp_transform_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit), [selected_esp_transform]);

                if Utils.is_hit_smaller(rhit, ihit):
                    self.cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit), selected_cipher);
                else:
                    self.cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit), selected_cipher);
                keymat_length_in_octets = Utils.compute_keymat_length(hmac_alg, selected_cipher);
                keymat = Utils.kdf(hmac_alg, salt, Math.int_to_bytes(shared_secret), info, keymat_length_in_octets);
                self.keymat_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                    Utils.ipv6_bytes_to_hex_formatted(ihit), keymat);
                logging.debug("Saving keying material in R1 %s %s" % (dst_str, src_str))

                logging.debug("Processing R1 packet %f" % (time.time() - st));

                st = time.time();

                # Transition to I2 state
                hip_i2_packet = HIP.I2Packet();
                hip_i2_packet.set_senders_hit(rhit);
                hip_i2_packet.set_receivers_hit(ihit);
                hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_i2_packet.set_version(HIP.HIP_VERSION);

                solution_param = HIP.SolutionParameter(buffer = None, rhash_length = r_hash.LENGTH);
                solution_param.set_k_value(puzzle_param.get_k_value());
                solution_param.set_opaque(opaque);
                solution_param.set_random(irandom, r_hash.LENGTH);
                solution_param.set_solution(jrandom, r_hash.LENGTH);

                dh_param = HIP.DHParameter();
                dh_param.set_group_id(selected_dh_group);
                dh_param.add_public_value(dh.encode_public_key());

                cipher_param = HIP.CipherParameter();
                cipher_param.add_ciphers([selected_cipher]);

                esp_tranform_param = HIP.ESPTransformParameter();
                esp_tranform_param.add_suits([selected_esp_transform]);

                keymat_index = Utils.compute_hip_keymat_length(hmac_alg, selected_cipher);

                esp_info_param = HIP.ESPInfoParameter();
                esp_info_param.set_keymat_index(keymat_index);
                esp_info_param.set_new_spi(Math.bytes_to_int(Utils.generate_random(HIP.HIP_ESP_INFO_NEW_SPI_LENGTH)));

                # Keying material generation
                # https://tools.ietf.org/html/rfc7402#section-7

                hi_param = HIP.HostIdParameter();
                hi_param.set_host_id(self.hi);
                hi_param.set_domain_id(self.di);

                transport_param = HIP.TransportListParameter();
                transport_param.add_transport_formats(self.config["security"]["supported_transports"]);

                mac_param = HIP.MACParameter();

                # Compute HMAC here
                buf = esp_info_param.get_byte_buffer();
                if r1_counter_param:
                    buf += r1_counter_param.get_byte_buffer();

                buf += solution_param.get_byte_buffer() + \
                        dh_param.get_byte_buffer() + \
                        cipher_param.get_byte_buffer() + \
                        esp_tranform_param.get_byte_buffer() + \
                        hi_param.get_byte_buffer();

                if echo_signed:
                    buf += echo_signed.get_byte_buffer();

                buf += transport_param.get_byte_buffer();

                original_length = hip_i2_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_i2_packet.set_length(int(packet_length / 8));
                buf = hip_i2_packet.get_buffer() + buf;
                # R1 packet incomming, IHIT - sender (Initiator), RHIT - own HIT (responder)
                # From this two we need to choose
                (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, rhit, ihit);
                hmac = HMACFactory.get(hmac_alg, hmac_key);
                mac_param.set_hmac(hmac.digest(bytearray(buf)));

                # Compute signature here
                
                hip_i2_packet = HIP.I2Packet();
                hip_i2_packet.set_senders_hit(rhit);
                hip_i2_packet.set_receivers_hit(ihit);
                hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_i2_packet.set_version(HIP.HIP_VERSION);
                hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                buf = esp_info_param.get_byte_buffer();

                if r1_counter_param:
                    buf += r1_counter_param.get_byte_buffer();

                buf += solution_param.get_byte_buffer() + \
                        dh_param.get_byte_buffer() + \
                        cipher_param.get_byte_buffer() + \
                        esp_tranform_param.get_byte_buffer() + \
                        hi_param.get_byte_buffer();

                if echo_signed:
                    buf += echo_signed.get_byte_buffer();

                buf += transport_param.get_byte_buffer() + \
                        mac_param.get_byte_buffer();
                
                original_length = hip_i2_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_i2_packet.set_length(int(packet_length / 8));
                buf = hip_i2_packet.get_buffer() + buf;
                #signature_alg = RSASHA256Signature(privkey.get_key_info());
                if isinstance(self.privkey, RSAPrivateKey):
                    signature_alg = RSASHA256Signature(self.privkey.get_key_info());
                elif isinstance(self.privkey, ECDSAPrivateKey):
                    signature_alg = ECDSASHA384Signature(self.privkey.get_key_info());
                elif isinstance(self.privkey, ECDSALowPrivateKey):
                    signature_alg = ECDSASHA1Signature(self.privkey.get_key_info());

                signature = signature_alg.sign(bytearray(buf));

                signature_param = HIP.SignatureParameter();
                signature_param.set_signature_algorithm(self.config["security"]["sig_alg"]);
                signature_param.set_signature(signature);

                total_param_length = 0;

                hip_i2_packet = HIP.I2Packet();
                hip_i2_packet.set_senders_hit(rhit);
                hip_i2_packet.set_receivers_hit(ihit);
                hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_i2_packet.set_version(HIP.HIP_VERSION);
                hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                hip_i2_packet.add_parameter(esp_info_param);
                if r1_counter_param:
                    hip_i2_packet.add_parameter(r1_counter_param);
                hip_i2_packet.add_parameter(solution_param);
                hip_i2_packet.add_parameter(dh_param);
                hip_i2_packet.add_parameter(cipher_param);
                hip_i2_packet.add_parameter(esp_tranform_param)
                hip_i2_packet.add_parameter(hi_param);
                if echo_signed:
                    hip_i2_packet.add_parameter(echo_signed);
                hip_i2_packet.add_parameter(transport_param);
                hip_i2_packet.add_parameter(mac_param);
                hip_i2_packet.add_parameter(signature_param);
                for unsigned_param in echo_unsigned:
                    hip_i2_packet.add_parameter(unsigned_param);

                # Swap the addresses
                temp = src;
                src = dst;
                dst = temp;

                # Calculate the checksum
                checksum = Utils.hip_ipv4_checksum(
                    src, 
                    dst, 
                    HIP.HIP_PROTOCOL, 
                    hip_i2_packet.get_length() * 8 + 8, 
                    hip_i2_packet.get_buffer());
                hip_i2_packet.set_checksum(checksum);

                buf = hip_i2_packet.get_buffer();
                
                total_length = len(buf);
                fragment_len = HIP.HIP_FRAGMENT_LENGTH;
                num_of_fragments = int(ceil(total_length / fragment_len))
                offset = 0;
                # Create IPv4 packet
                ipv4_packet = IPv4.IPv4Packet();
                ipv4_packet.set_version(IPv4.IPV4_VERSION);
                ipv4_packet.set_destination_address(dst);
                ipv4_packet.set_source_address(src);
                ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
                ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);
                #	# Send the packet
                ipv4_packet.set_payload(buf);
                dst_str = Utils.ipv4_bytes_to_string(dst);
                    
                logging.debug(list(ipv4_packet.get_buffer()));

                logging.debug("Sending I2 packet to %s %d" % (dst_str, len(ipv4_packet.get_buffer())));
                response.append((bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0)))

                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                        Utils.ipv6_bytes_to_hex_formatted(rhit));
                sv.i2_packet = ipv4_packet;

                if hip_state.is_i1_sent() or hip_state.is_closing() or hip_state.is_closed():
                    hip_state.i2_sent();
            elif hip_packet.get_packet_type() == HIP.HIP_I2_PACKET:
                logging.info("---------------------------- I2 packet ---------------------------- ");
                st = time.time();
                
                if hip_state.is_i2_sent() and Utils.is_hit_smaller(rhit, ihit):
                    logging.debug("Staying in I2-SENT state. Dropping the packet...");
                    return [];
            
                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                            Utils.ipv6_bytes_to_hex_formatted(ihit))
                    
                    if not sv:
                        sv = HIPState.StateVariables(hip_state.get_state(), ihit, rhit, dst, src)
                     
                        self.state_variables.save(Utils.ipv6_bytes_to_hex_formatted(rhit),
                            Utils.ipv6_bytes_to_hex_formatted(ihit),
                            sv)
                        sv.is_responder = True;
                        sv.ihit = ihit;
                        sv.rhit = rhit;
                    else:
                        sv.state = hip_state.get_state()
                        sv.is_responder = True;
                        sv.ihit = ihit;
                        sv.rhit = rhit;
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                            Utils.ipv6_bytes_to_hex_formatted(rhit))
                            
                    if not sv:
                        sv = HIPState.StateVariables(hip_state.get_state(), ihit, rhit, dst, src)
                        self.state_variables.save(Utils.ipv6_bytes_to_hex_formatted(ihit),
                            Utils.ipv6_bytes_to_hex_formatted(rhit),
                            sv)
                        sv.is_responder = True;
                        sv.ihit = ihit;
                        sv.rhit = rhit;
                    else:
                        sv.state = hip_state.get_state()
                        sv.is_responder = True;
                        sv.ihit = ihit;
                        sv.rhit = rhit;

                solution_param     = None;
                r1_counter_param   = None;
                dh_param           = None;
                cipher_param       = None;
                esp_tranform_param = None;
                esp_info_param     = None;
                hi_param           = None;
                transport_param    = None;
                mac_param          = None;
                signature_param    = None;
                echo_signed        = None;
                parameters         = hip_packet.get_parameters();
                iv_length          = None;
                encrypted_param    = None;

                initiators_spi     = None;
                initiators_keymat_index = None;

                for parameter in parameters:
                    if isinstance(parameter, HIP.ESPInfoParameter):
                        logging.debug("ESP info parameter")
                        esp_info_param = parameter;
                    if isinstance(parameter, HIP.R1CounterParameter):
                        logging.debug("R1 counter");
                        r1_counter_param = parameter;
                    if isinstance(parameter, HIP.SolutionParameter):
                        logging.debug("Puzzle solution parameter");
                        solution_param = parameter;
                    if isinstance(parameter, HIP.DHParameter):	
                        logging.debug("DH parameter");
                        dh_param = parameter;
                    if isinstance(parameter, HIP.EncryptedParameter):
                        logging.debug("Encrypted parameter");
                        encrypted_param = parameter;
                    if isinstance(parameter, HIP.HostIdParameter):
                        logging.debug("Host ID");
                        hi_param = parameter;
                        #responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
                        #if hi_param.get_algorithm() != self.config["security"]["sig_alg"]:
                        #	logging.critical("Invalid signature algorithm");
                        #	return;
                        if hi_param.get_algorithm() == 0x5: #RSA
                            responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
                        elif hi_param.get_algorithm() == 0x7: #ECDSA
                            responder_hi = ECDSAHostID.from_byte_buffer(hi_param.get_host_id());
                        elif hi_param.get_algorithm() == 0x9: #ECDSA LOW
                            responder_hi = ECDSALowHostID.from_byte_buffer(hi_param.get_host_id());
                        else:
                            raise Exception("Invalid signature algorithm");
                        oga = HIT.get_responders_oga_id(ihit);
                        logging.debug("OGA ID %d " % (oga));
                        responders_hit = HIT.get(responder_hi.to_byte_array(), oga);

                        if ihit != responders_hit:
                            raise Exception("Invalid source HIT")
                        if rhit != self.own_hit:
                            raise Exception("Invalid destination HIT")
                        
                        logging.debug(list(rhit));
                        logging.debug(list(ihit));
                        logging.debug(list(responders_hit));
                        if not Utils.hits_equal(ihit, responders_hit):
                            logging.critical("Invalid HIT");
                            raise Exception("Invalid HIT");

                        if isinstance(responder_hi, RSAHostID): #RSA
                            responders_public_key = RSAPublicKey.load_from_params(
                                responder_hi.get_exponent(), 
                                responder_hi.get_modulus());
                        elif isinstance(responder_hi, ECDSAHostID): #ECDSA
                            responders_public_key = ECDSAPublicKey.load_from_params(
                                responder_hi.get_curve_id(), 
                                responder_hi.get_x(),
                                responder_hi.get_y());
                        elif isinstance(responder_hi, ECDSALowHostID): #ECDSA LOW
                            responders_public_key = ECDSALowPublicKey.load_from_params(
                                responder_hi.get_curve_id(), 
                                responder_hi.get_x(),
                                responder_hi.get_y());
                        else:
                            raise Exception("Invalid signature algorithm");

                        self.pubkey_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                            Utils.ipv6_bytes_to_hex_formatted(rhit), 
                            responders_public_key);
                    if isinstance(parameter, HIP.TransportListParameter):
                        logging.debug("Transport parameter");
                        transport_param = parameter;
                    if isinstance(parameter, HIP.SignatureParameter):
                        logging.debug("Signature parameter");
                        signature_param = parameter;
                    if isinstance(parameter, HIP.CipherParameter):
                        logging.debug("Ciphers parameter");
                        cipher_param = parameter;
                    if isinstance(parameter, HIP.ESPTransformParameter):
                        logging.debug("ESP transform parameter");
                        esp_tranform_param = parameter;
                    if isinstance(parameter, HIP.MACParameter):
                        logging.debug("MAC parameter");	
                        mac_param = parameter;
                    if isinstance(parameter, HIP.EchoResponseSignedParameter):
                        logging.debug("Echo response signed");
                        echo_signed = parameter;
                if not solution_param:
                    logging.critical("Missing solution parameter");
                    return [];
                if not dh_param:
                    logging.critical("Missing DH parameter");
                    return [];
                if not cipher_param:
                    logging.critical("Missing cipher parameter");
                    return [];
                if not esp_info_param:
                    logging.critical("Missing ESP info parameter");
                    return [];
                if not hi_param:
                    logging.critical("Missing HI parameter");
                    return [];
                if not transport_param:
                    logging.critical("Missing transport parameter");
                    return [];
                if not signature_param:
                    logging.critical("Missing signature parameter");
                    return [];
                if not mac_param:
                    logging.critical("Missing MAC parameter");
                    return [];
                
                oga = HIT.get_responders_oga_id(rhit);

                if (oga << 4) not in self.config["security"]["supported_hit_suits"]:
                    logging.critical("Unsupported HIT suit");
                    logging.critical("OGA %d"  % (oga));
                    logging.critical(self.config["security"]["supported_hit_suits"]);
                    return [];

                if hip_state.is_i2_sent():
                    if Utils.is_hit_smaller(rhit, ihit):
                        logging.debug("Dropping I2 packet...");
                        return [];

                r_hash = HIT.get_responders_hash_algorithm(rhit);
                jrandom = solution_param.get_solution(r_hash.LENGTH);
                irandom = solution_param.get_random(r_hash.LENGTH);
                if not PuzzleSolver.verify_puzzle(
                     irandom, 
                    jrandom, 
                    hip_packet.get_senders_hit(), 
                    hip_packet.get_receivers_hit(), 
                    solution_param.get_k_value(), r_hash):
                    logging.debug("Puzzle was not solved....");
                    return [];
                logging.debug("Puzzle was solved");

                dh = self.dh_storage[r1_counter_param.get_counter()].get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(rhit));

                public_key_r = dh.decode_public_key(dh_param.get_public_value());
                shared_secret = dh.compute_shared_secret(public_key_r);

                info = Utils.sort_hits(ihit, rhit);
                salt = irandom + jrandom;
                hmac_alg  = HIT.get_responders_oga_id(rhit);

                key_info = HIPState.KeyInfo(info, salt, dh.ALG_ID);

                if Utils.is_hit_smaller(rhit, ihit):
                    self.key_info_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit), key_info);
                else:
                    self.key_info_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit), key_info);

                offered_ciphers = cipher_param.get_ciphers();
                supported_ciphers = self.config["security"]["supported_ciphers"];
                selected_cipher = None;

                for cipher in offered_ciphers:
                    if cipher in supported_ciphers:
                        selected_cipher = cipher;
                        break;

                if not selected_cipher:
                    logging.critical("Unsupported cipher");
                    # Transition to unassociated state
                    raise Exception("Unsupported cipher");

                if len(esp_tranform_param.get_suits()) == 0:
                    logging.critical("ESP transform suit was not negotiated.")
                    raise Exception("ESP transform suit was not negotiated.");

                selected_esp_transform = esp_tranform_param.get_suits()[0];

                initiators_spi = esp_info_param.get_new_spi();
                initiators_keymat_index = esp_info_param.get_keymat_index();

                keymat_length_in_octets = Utils.compute_keymat_length(hmac_alg, selected_cipher);
                keymat = Utils.kdf(hmac_alg, salt, Math.int_to_bytes(shared_secret), info, keymat_length_in_octets);

                self.keymat_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                	Utils.ipv6_bytes_to_hex_formatted(rhit), keymat);
                
                logging.debug("Saving keying material in I2 %s %s" % (dst_str, src_str))

                if Utils.is_hit_smaller(rhit, ihit):
                    self.cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit), selected_cipher);
                else:
                    self.cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit), selected_cipher);
                #cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                #	Utils.ipv6_bytes_to_hex_formatted(rhit), selected_cipher);

                if encrypted_param:
                    # I2 packet incomming, IHIT - sender (Initiator), RHIT - own HIT (responder)
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, ihit, rhit);
                    cipher = SymmetricCiphersFactory.get(selected_cipher);
                    iv_length = cipher.BLOCK_SIZE;
                    iv = encrypted_param.get_iv(iv_length);
                    data = encrypted_param.get_encrypted_data(iv_length);
                    host_id_data = cipher.decrypt(aes_key, iv, data);
                    hi_param = HIP.HostIdParameter(host_id_data);
                    #responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
                    #if hi_param.get_algorithm() != self.config["security"]["sig_alg"]:
                    #	logging.critical("Invalid signature algorithm");
                    #	raise Exception("Invalid signature algorithm");
                    if hi_param.get_algorithm() == 0x5: #RSA
                        responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
                    elif hi_param.get_algorithm() == 0x7: #ECDSA
                        responder_hi = ECDSAHostID.from_byte_buffer(hi_param.get_host_id());
                    elif hi_param.get_algorithm() == 0x9: #ECDSA LOW
                        responder_hi = ECDSALowHostID.from_byte_buffer(hi_param.get_host_id());
                    else:
                        raise Exception("Invalid signature algorithm");
                    oga = HIT.get_responders_oga_id(rhit);
                    responders_hit = HIT.get(responder_hi.to_byte_array(), oga);
                    if not Utils.hits_equal(ihit, responders_hit):
                        logging.critical("Invalid HIT");
                        raise Exception("Invalid HIT");
                    
                    if isinstance(responder_hi, RSAHostID): #RSA
                        responders_public_key = RSAPublicKey.load_from_params(
                            responder_hi.get_exponent(), 
                            responder_hi.get_modulus());
                    elif isinstance(responder_hi, ECDSAHostID): #ECDSA
                        responders_public_key = ECDSAPublicKey.load_from_params(
                            responder_hi.get_curve_id(), 
                            responder_hi.get_x(),
                            responder_hi.get_y());
                    elif isinstance(responder_hi, ECDSALowHostID): #ECDSA LOW
                        responders_public_key = ECDSALowPublicKey.load_from_params(
                            responder_hi.get_curve_id(), 
                            responder_hi.get_x(),
                            responder_hi.get_y());
                    else:
                        raise Exception("Invalid signature algorithm");

                hip_i2_packet = HIP.I2Packet();
                hip_i2_packet.set_senders_hit(ihit);
                hip_i2_packet.set_receivers_hit(rhit);
                hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_i2_packet.set_version(HIP.HIP_VERSION);
                hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                # Compute HMAC here
                buf = esp_info_param.get_byte_buffer();
                if r1_counter_param:
                    buf += r1_counter_param.get_byte_buffer();

                buf += solution_param.get_byte_buffer() + \
                        dh_param.get_byte_buffer() + \
                        cipher_param.get_byte_buffer() + \
                        esp_tranform_param.get_byte_buffer() + \
                        hi_param.get_byte_buffer();

                if echo_signed:
                    buf += echo_signed.get_byte_buffer();

                buf += transport_param.get_byte_buffer();

                original_length = hip_i2_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_i2_packet.set_length(int(packet_length / 8));
                buf = hip_i2_packet.get_buffer() + buf;
                
                # I2 packet incomming, IHIT - sender (Initiator), RHIT - own HIT (responder)
                (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, ihit, rhit);
                hmac = HMACFactory.get(hmac_alg, hmac_key);

                if hmac.digest(buf) != mac_param.get_hmac():
                    logging.critical("Invalid HMAC (I2). Dropping the packet");
                    return [];

                # Compute signature here
                hip_i2_packet = HIP.I2Packet();
                hip_i2_packet.set_senders_hit(ihit);
                hip_i2_packet.set_receivers_hit(rhit);
                hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_i2_packet.set_version(HIP.HIP_VERSION);
                hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                buf = esp_info_param.get_byte_buffer();
                if r1_counter_param:
                    buf += r1_counter_param.get_byte_buffer();

                buf += solution_param.get_byte_buffer() + \
                        dh_param.get_byte_buffer() + \
                        cipher_param.get_byte_buffer() + \
                        esp_tranform_param.get_byte_buffer() + \
                        hi_param.get_byte_buffer();

                if echo_signed:
                    buf += echo_signed.get_byte_buffer();

                buf += transport_param.get_byte_buffer() + \
                        mac_param.get_byte_buffer();
                
                original_length = hip_i2_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                
                hip_i2_packet.set_length(int(packet_length / 8));
                buf = hip_i2_packet.get_buffer() + buf;

                #signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
                if isinstance(responders_public_key, RSAPublicKey):
                    signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSAPublicKey):
                    signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSALowPublicKey):
                    signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());

                if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
                    logging.critical("Invalid signature. Dropping the packet");
                else:
                    logging.debug("Signature is correct");

                logging.debug("Processing I2 packet %f" % (time.time() - st));
                
                st = time.time();

                hip_r2_packet = HIP.R2Packet();
                hip_r2_packet.set_senders_hit(rhit);
                hip_r2_packet.set_receivers_hit(ihit);
                hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_r2_packet.set_version(HIP.HIP_VERSION);
                hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                keymat_index = Utils.compute_hip_keymat_length(hmac_alg, selected_cipher);
                responders_spi = Math.bytes_to_int(Utils.generate_random(HIP.HIP_ESP_INFO_NEW_SPI_LENGTH));

                if initiators_keymat_index != keymat_index:
                    raise Exception("Keymat index should match....")

                esp_info_param = HIP.ESPInfoParameter();
                esp_info_param.set_keymat_index(keymat_index);
                esp_info_param.set_new_spi(responders_spi);

                hip_r2_packet.add_parameter(esp_info_param);

                # R2 packet outgoing, IHIT - sender (Initiator), RHIT - own HIT (responder), IHIT - 1, RHIT - 2
                (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, rhit, ihit);
                hmac = HMACFactory.get(hmac_alg, hmac_key);

                hip_r2_packet.add_parameter(self.own_hi_param)

                mac_param = HIP.MAC2Parameter();
                mac_param.set_hmac(hmac.digest(bytearray(hip_r2_packet.get_buffer())));

                # Compute signature here
                
                hip_r2_packet = HIP.R2Packet();
                hip_r2_packet.set_senders_hit(rhit);
                hip_r2_packet.set_receivers_hit(ihit);
                hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_r2_packet.set_version(HIP.HIP_VERSION);
                hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                
                buf = mac_param.get_byte_buffer();				
                original_length = hip_r2_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_r2_packet.set_length(int(packet_length / 8));
                buf = hip_r2_packet.get_buffer() + buf;
                #signature_alg = RSASHA256Signature(privkey.get_key_info());
                if isinstance(self.privkey, RSAPrivateKey):
                    signature_alg = RSASHA256Signature(self.privkey.get_key_info());
                elif isinstance(self.privkey, ECDSAPrivateKey):
                    signature_alg = ECDSASHA384Signature(self.privkey.get_key_info());
                elif isinstance(self.privkey, ECDSALowPrivateKey):
                    signature_alg = ECDSASHA1Signature(self.privkey.get_key_info());

                signature = signature_alg.sign(bytearray(buf));

                signature_param = HIP.Signature2Parameter();
                signature_param.set_signature_algorithm(self.config["security"]["sig_alg"]);
                signature_param.set_signature(signature);

                hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                hip_r2_packet.add_parameter(esp_info_param);
                hip_r2_packet.add_parameter(mac_param);
                hip_r2_packet.add_parameter(signature_param);
                
                # Swap the addresses
                temp = src;
                src = dst;
                dst = temp;

                # Create IPv4 packet
                ipv4_packet = IPv4.IPv4Packet();
                ipv4_packet.set_version(IPv4.IPV4_VERSION);
                ipv4_packet.set_destination_address(dst);
                ipv4_packet.set_source_address(src);
                ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
                ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

                # Calculate the checksum
                checksum = Utils.hip_ipv4_checksum(
                    src, 
                    dst, 
                    HIP.HIP_PROTOCOL, 
                    hip_r2_packet.get_length() * 8 + 8, 
                    hip_r2_packet.get_buffer());
                hip_r2_packet.set_checksum(checksum);
                ipv4_packet.set_payload(hip_r2_packet.get_buffer());
                # Send the packet
                dst_str = Utils.ipv4_bytes_to_string(dst);
                src_str = Utils.ipv4_bytes_to_string(src);
                
                # Transition to an Established state
                logging.debug("Current system state is %s" % (str(hip_state)));
                
                if (hip_state.is_established() 
                    or hip_state.is_unassociated() 
                    or hip_state.is_i1_sent() 
                    or hip_state.is_i2_sent() 
                    or hip_state.is_r2_sent()
                    or hip_state.is_closing()
                    or hip_state.is_closed()):
                    hip_state.r2_sent();
                    logging.debug("Sending R2 packet to %s %f" % (dst_str, time.time() - st));
                    response.append((bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0)))

                logging.debug("Setting SA records...");

                (cipher, hmac) = ESPTransformFactory.get(selected_esp_transform);

                logging.debug("DERIVING KEYS")
                logging.debug(keymat)
                # I2 PACKET
                # Responder
                # OUT DIRECTION (IHIT - sender, RHIT - OWN)
                # The first key out is for larger HIT
                # If OWN HIT is larger then we SHOULD use the first key 
                # THen we should pass the larger (or own) HIT first
                #if Utils.is_hit_smaller(ihit, rhit):
                (cipher_key, hmac_key) = Utils.get_keys_esp(
                        keymat,
                        keymat_index, 
                        hmac.ALG_ID, 
                        cipher.ALG_ID,
                        rhit, ihit);
                
                
                logging.debug(" DERVIVING KEYS OUT I2")
                logging.debug(hexlify(hmac_key))
                logging.debug(hexlify(cipher_key))
                logging.debug(hexlify(self.own_hit))
                
                logging.debug(hexlify(ihit))
                logging.debug(hexlify(rhit))
                
                sa_record = SA.SecurityAssociationRecord(cipher.ALG_ID, hmac.ALG_ID, cipher_key, hmac_key, src, dst);
                sa_record.set_spi(responders_spi);
                self.ip_sec_sa.add_record(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                    Utils.ipv6_bytes_to_hex_formatted(ihit), sa_record);

                
                # IN DIRECTION (IHIT - sender, RHIT - OWN)
                """
                (cipher_key, hmac_key) = Utils.get_keys_esp(
                    keymat, 
                    keymat_index, 
                    hmac.ALG_ID, 
                    cipher.ALG_ID, 
                    rhit, ihit);
                """

                # If OWN HIT is smaller then we SHOULD use the first key 
                # THen we should pass the larger (or own) HIT first
                (cipher_key, hmac_key) = Utils.get_keys_esp(
                    keymat,
                    keymat_index, 
                    hmac.ALG_ID, 
                    cipher.ALG_ID,
                    ihit, rhit);
                

                logging.debug(" DERVIVING KEYS IN I2")
                logging.debug(hexlify(hmac_key))
                logging.debug(hexlify(cipher_key))

                logging.debug(hexlify(self.own_hit))
                logging.debug(hexlify(rhit))
                logging.debug(hexlify(ihit))

                sa_record = SA.SecurityAssociationRecord(cipher.ALG_ID, hmac.ALG_ID, cipher_key, hmac_key, rhit, ihit);
                sa_record.set_spi(initiators_spi);
                self.ip_sec_sa.add_record(dst_str, src_str, sa_record);
                
                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                        Utils.ipv6_bytes_to_hex_formatted(rhit));
                
                sv.ec_complete_timeout = time.time() + self.config["general"]["EC"];
            elif hip_packet.get_packet_type() == HIP.HIP_R2_PACKET:
                
                if (hip_state.is_unassociated() 
                    or hip_state.is_i1_sent() 
                    or hip_state.is_r2_sent() 
                    or hip_state.is_established()
                    or hip_state.is_closing()
                    or hip_state.is_closed()):
                    logging.debug("Dropping the packet");
                    return [];

                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                            Utils.ipv6_bytes_to_hex_formatted(ihit))
                    
                    if not sv:
                        sv = HIPState.StateVariables(hip_state.get_state(), rhit, ihit, dst, src)
                     
                        self.state_variables.save(Utils.ipv6_bytes_to_hex_formatted(rhit),
                            Utils.ipv6_bytes_to_hex_formatted(ihit),
                            sv)
                        sv.is_responder = False;
                        sv.ihit = rhit;
                        sv.rhit = ihit;
                    else:
                        sv.state = hip_state.get_state()
                        sv.is_responder = False;
                        sv.ihit = rhit;
                        sv.rhit = ihit;
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                            Utils.ipv6_bytes_to_hex_formatted(rhit))
                            
                    if not sv:
                        sv = HIPState.StateVariables(hip_state.get_state(), rhit, ihit, dst, src)
                        self.state_variables.save(Utils.ipv6_bytes_to_hex_formatted(ihit),
                            Utils.ipv6_bytes_to_hex_formatted(rhit),
                            sv)
                        sv.is_responder = False;
                        sv.ihit = rhit;
                        sv.rhit = ihit;
                    else:
                        sv.state = hip_state.get_state()
                        sv.is_responder = False;
                        sv.ihit = rhit;
                        sv.rhit = ihit;
                
                st = time.time();

                logging.info("R2 packet");
                
                hmac_alg  = HIT.get_responders_oga_id(ihit);

                if Utils.is_hit_smaller(rhit, ihit):
                    cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit));
                keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                	Utils.ipv6_bytes_to_hex_formatted(ihit));
                # R2 packet incomming, IHIT - sender (Responder), RHIT - own HIT (Initiator)
                (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, ihit, rhit);
                hmac = HMACFactory.get(hmac_alg, hmac_key);
                parameters       = hip_packet.get_parameters();
                
                esp_info_param  = None;
                hmac_param      = None;
                signature_param = None;

                initiators_spi          = None;
                responders_spi          = None;
                keymat_index            = None;

                for parameter in parameters:
                    if isinstance(parameter, HIP.ESPInfoParameter):
                        logging.debug("ESP info parameter");
                        esp_info_param = parameter;
                    if isinstance(parameter, HIP.Signature2Parameter):
                        logging.debug("Signature2 parameter");
                        signature_param = parameter;
                    if isinstance(parameter, HIP.MAC2Parameter):
                        logging.debug("MAC2 parameter");	
                        hmac_param = parameter;
                
                if not esp_info_param:
                    logging.critical("Missing ESP info parameter");
                    return [];

                if not hmac_param:
                    logging.critical("Missing HMAC parameter");
                    return [];

                if not signature_param:
                    logging.critical("Missing signature parameter");
                    return [];

                hip_r2_packet = HIP.R2Packet();
                hip_r2_packet.set_senders_hit(ihit);
                hip_r2_packet.set_receivers_hit(rhit);
                hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_r2_packet.set_version(HIP.HIP_VERSION);
                hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                hip_r2_packet.add_parameter(esp_info_param);

                if Utils.is_hit_smaller(rhit, ihit):
                    hi_param = self.hi_param_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    hi_param = self.hi_param_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit));
                
                hip_r2_packet.add_parameter(hi_param)

                if hmac.digest(hip_r2_packet.get_buffer()) != hmac_param.get_hmac():
                    logging.critical("Invalid HMAC (R2). Dropping the packet");
                    return [];
                else:
                    logging.debug("HMAC is ok. return with signature");

                buf = bytearray([]);
                hip_r2_packet = HIP.R2Packet();
                hip_r2_packet.set_senders_hit(ihit);
                hip_r2_packet.set_receivers_hit(rhit);
                hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_r2_packet.set_version(HIP.HIP_VERSION);
                hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                #hip_r2_packet.add_parameter(hmac_param);
                buf = hmac_param.get_byte_buffer();
                original_length = hip_r2_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_r2_packet.set_length(int(packet_length / 8));
                buf = hip_r2_packet.get_buffer() + buf;

                responders_public_key = self.pubkey_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                            Utils.ipv6_bytes_to_hex_formatted(rhit));

                if isinstance(responders_public_key, RSAPublicKey):
                    signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSAPublicKey):
                    signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSALowPublicKey):
                    signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());
                
                if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
                    logging.critical("Invalid signature. Dropping the packet");
                else:
                    logging.debug("Signature is correct");

                responders_spi = esp_info_param.get_new_spi();
                keymat_index = esp_info_param.get_keymat_index();

                logging.debug("Processing R2 packet %f" % (time.time() - st));
                logging.debug("Ending HIP BEX %f" % (time.time()));

                dst_str = Utils.ipv4_bytes_to_string(dst);
                src_str = Utils.ipv4_bytes_to_string(src);

                logging.debug("Setting SA records... %s - %s" % (src_str, dst_str));

                if Utils.is_hit_smaller(rhit, ihit):
                    selected_esp_transform = self.esp_transform_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit))[0];
                else:
                    selected_esp_transform = self.esp_transform_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit))[0];

                (cipher, hmac) = ESPTransformFactory.get(selected_esp_transform);

                logging.debug(hmac.ALG_ID);
                logging.debug(cipher.ALG_ID);
                
                logging.debug("DERIVING KEYS")
                logging.debug(keymat)

                # Incomming SA (IPa, IPb)
                # R2 PACKET
                # Initiator
                # OUT DIRECTION (IHIT - sender, RHIT - OWN)
                # If OWN HIT is larger then we SHOULD use the first key 
                #if Utils.is_hit_smaller(ihit, rhit):
                (cipher_key, hmac_key) = Utils.get_keys_esp(
                    keymat,
                    keymat_index, 
                    hmac.ALG_ID, 
                    cipher.ALG_ID,
                    rhit, ihit);
                # If OWN HIT is smaller we should use the second key
                """else:
                    (cipher_key, hmac_key) = Utils.get_keys_esp(
                        keymat, 
                        keymat_index, 
                        hmac.ALG_ID, 
                        cipher.ALG_ID, 
                        rhit, ihit);
                """
                logging.debug(" DERVIVING KEYS OUT R2")
                logging.debug(hexlify(hmac_key))
                logging.debug(hexlify(cipher_key))

                logging.debug(hexlify(self.own_hit))
                logging.debug(hexlify(ihit))
                logging.debug(hexlify(rhit))
                
                sa_record = SA.SecurityAssociationRecord(cipher.ALG_ID, hmac.ALG_ID, cipher_key, hmac_key, dst, src);
                sa_record.set_spi(responders_spi);
                
                self.ip_sec_sa.add_record(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                    Utils.ipv6_bytes_to_hex_formatted(ihit), sa_record);
                
                # Outgoing SA (HITa, HITb)
                # IN DIRECTION (IHIT - sender, RHIT - OWN)
                
                (cipher_key, hmac_key) = Utils.get_keys_esp(
                    keymat, 
                    keymat_index, 
                    hmac.ALG_ID, 
                    cipher.ALG_ID, 
                    ihit, rhit);
                
                # If OWN HIT is smaller then we SHOULD use the first key 
                # THen we should pass the larger (or own) HIT first
                """if Utils.is_hit_smaller(rhit, ihit):
                    (cipher_key, hmac_key) = Utils.get_keys_esp(
                        keymat,
                        keymat_index, 
                        hmac.ALG_ID, 
                        cipher.ALG_ID,
                        ihit, rhit);
                # If OWN HIT is larger we should use the second key
                # THen we should pass the larger (or own) HIT also first
                else:
                    (cipher_key, hmac_key) = Utils.get_keys_esp(
                        keymat, 
                        keymat_index, 
                        hmac.ALG_ID, 
                        cipher.ALG_ID, 
                        ihit, rhit);
                """
                logging.debug(" DERVIVING KEYS IN R2")
                logging.debug(hexlify(hmac_key))
                logging.debug(hexlify(cipher_key))

                logging.debug(hexlify(self.own_hit))
                logging.debug(hexlify(rhit))
                logging.debug(hexlify(ihit))
                
                sa_record = SA.SecurityAssociationRecord(cipher.ALG_ID, hmac.ALG_ID, cipher_key, hmac_key, rhit, ihit);
                sa_record.set_spi(responders_spi);
                self.ip_sec_sa.add_record(src_str, dst_str, sa_record);

                # Transition to an Established state
                hip_state.established();
                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                        Utils.ipv6_bytes_to_hex_formatted(rhit));
                sv.data_timeout = time.time() + self.config["general"]["UAL"];
                #sv.state = HIPState.HIP_STATE_ESTABLISHED;
            elif hip_packet.get_packet_type() == HIP.HIP_UPDATE_PACKET:
                logging.info("UPDATE packet");
                if (hip_state.is_i1_sent() 
                    or hip_state.is_unassociated() 
                    or hip_state.is_i2_sent() 
                    or hip_state.is_closing()
                    or hip_state.is_closed()):
                    logging.debug("Dropping the packet");
                    return [];
                # Process the packet
                parameters       = hip_packet.get_parameters();

                ack_param        = None;
                seq_param        = None;
                signature_param  = None;
                mac_param        = None;
                dh_param         = None;
                esp_info         = None;

                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                        Utils.ipv6_bytes_to_hex_formatted(rhit));
                keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
                if sv.is_responder:
                    
                    logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(ihit)))
                    logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(rhit)))
                    hmac_alg  = HIT.get_responders_oga_id(rhit);
                    logging.debug("Responders's HMAC algorithm %d" % (hmac_alg))
                else:
                    logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(rhit)))
                    logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(ihit)))					
                    hmac_alg  = HIT.get_responders_oga_id(ihit);
                    logging.debug("Reponder's HMAC algorithm %d" % (hmac_alg))

                if Utils.is_hit_smaller(rhit, ihit):
                    cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit));
                # UPDATE packet incomming, IHIT - sender (Initiator), RHIT - own HIT (responder)
                if sv.is_responder:
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);
                else:
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
                hmac = HMACFactory.get(hmac_alg, hmac_key);

                for parameter in parameters:
                    if isinstance(parameter, HIP.AckParameter):
                        logging.debug("Acknowledgement parameter");
                        ack_param = parameter;
                    if isinstance(parameter, HIP.SequenceParameter):
                        logging.debug("Sequence parameter");
                        seq_param = parameter;
                    if isinstance(parameter, HIP.MACParameter):	
                        logging.debug("MAC parameter");
                        mac_param = parameter;
                    if isinstance(parameter, HIP.SignatureParameter):
                        logging.debug("Signature parameter");
                        signature_param = parameter;
                    if isinstance(parameter, HIP.DHParameter):
                        logging.debug("DH parameter");
                        dh_param = parameter;
                    if isinstance(parameter, HIP.ESPInfoParameter):
                        logging.debug("ESP info parameter");
                        esp_info_param = parameter;

                if not mac_param:
                    logging.debug("Missing MAC parameter");
                    return [];

                if not signature_param:
                    logging.debug("Missing signature parameter");
                    return [];
                
                hip_update_packet = HIP.UpdatePacket();
                hip_update_packet.set_senders_hit(ihit);
                hip_update_packet.set_receivers_hit(rhit);
                hip_update_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_update_packet.set_version(HIP.HIP_VERSION);
                hip_update_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                # Compute HMAC here
                buf = bytearray([]);
                if ack_param:
                    buf += ack_param.get_byte_buffer();
                if seq_param:
                    buf += seq_param.get_byte_buffer();
                

                original_length = hip_update_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_update_packet.set_length(int(packet_length / 8));
                buf = hip_update_packet.get_buffer() + buf;

                if hmac.digest(bytearray(buf)) != mac_param.get_hmac():
                    if ack_param:
                        logging.critical("Invalid HMAC (UPDATE ACK packet). Dropping the packet %s %s" % (src_str, dst_str))
                    else:
                        logging.critical("Invalid HMAC (UPDATE packet). Dropping the packet %s %s" % (src_str, dst_str));
                    return [];

                responders_public_key = self.pubkey_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                            Utils.ipv6_bytes_to_hex_formatted(rhit));
                
                if isinstance(responders_public_key, RSAPublicKey):
                    signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSAPublicKey):
                    signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSALowPublicKey):
                    signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());

                hip_update_packet = HIP.UpdatePacket();
                hip_update_packet.set_senders_hit(ihit);
                hip_update_packet.set_receivers_hit(rhit);
                hip_update_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_update_packet.set_version(HIP.HIP_VERSION);
                hip_update_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                buf = bytearray([]);
                if ack_param:
                    buf += ack_param.get_byte_buffer();
                if seq_param:
                    buf += seq_param.get_byte_buffer();
                buf += mac_param.get_byte_buffer();

                original_length = hip_update_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_update_packet.set_length(int(packet_length / 8));
                buf = hip_update_packet.get_buffer() + buf;

                if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
                    logging.critical("Invalid signature. Dropping the packet");
                    return [];
                else:
                    logging.debug("Signature is correct");

                if ack_param:
                    logging.debug("This is a response to a UPDATE. Skipping pong...");
                    return [];
                # UPDATE ACK packet outgoing, RHIT - own HIT (Initiator), IHIT - recipient
                # OUT DIRECTION
                if sv.is_responder:
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
                else:
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);
                #(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);

                hmac = HMACFactory.get(hmac_alg, hmac_key);

                hip_update_packet = HIP.UpdatePacket();
                hip_update_packet.set_senders_hit(rhit);
                hip_update_packet.set_receivers_hit(ihit);
                hip_update_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_update_packet.set_version(HIP.HIP_VERSION);
                hip_update_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                ack_param = HIP.AckParameter();
                ack_param.set_ids([seq_param.get_id()]);
                hip_update_packet.add_parameter(ack_param);

                mac_param = HIP.MACParameter();
                mac_param.set_hmac(hmac.digest(bytearray(hip_update_packet.get_buffer())));
                hip_update_packet.add_parameter(mac_param);

                if isinstance(self.privkey, RSAPrivateKey):
                    signature_alg = RSASHA256Signature(self.privkey.get_key_info());
                elif isinstance(self.privkey, ECDSAPrivateKey):
                    signature_alg = ECDSASHA384Signature(self.privkey.get_key_info());
                elif isinstance(self.privkey, ECDSALowPrivateKey):
                    signature_alg = ECDSASHA1Signature(self.privkey.get_key_info());

                signature = signature_alg.sign(bytearray(hip_update_packet.get_buffer()));

                signature_param = HIP.SignatureParameter();
                signature_param.set_signature_algorithm(self.config["security"]["sig_alg"]);
                signature_param.set_signature(signature);

                hip_update_packet.add_parameter(signature_param);

                # Swap the addresses
                temp = src;
                src = dst;
                dst = temp;

                # Create IPv4 packet
                ipv4_packet = IPv4.IPv4Packet();
                ipv4_packet.set_version(IPv4.IPV4_VERSION);
                ipv4_packet.set_destination_address(dst);
                ipv4_packet.set_source_address(src);
                ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
                ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

                # Calculate the checksum
                checksum = Utils.hip_ipv4_checksum(
                    src, 
                    dst, 
                    HIP.HIP_PROTOCOL, 
                    hip_update_packet.get_length() * 8 + 8, 
                    hip_update_packet.get_buffer());
                hip_update_packet.set_checksum(checksum);
                ipv4_packet.set_payload(hip_update_packet.get_buffer());
                # Send the packet
                dst_str = Utils.ipv4_bytes_to_string(dst);
                src_str = Utils.ipv4_bytes_to_string(src);
                
                logging.debug("Sending UPDATE ACK packet %s" % (dst_str));
                response.append((bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0)))

                if hip_state.is_r2_sent():
                    hip_state.established();
            elif hip_packet.get_packet_type() == HIP.HIP_NOTIFY_PACKET:
                logging.info("NOTIFY packet");
                if hip_state.is_i1_sent() or hip_state.is_i2_sent() or hip_state.is_unassociated() or hip_state.is_closing() or hip_state.closed():
                    logging.debug("Dropping the packet...")
                    return [];
                # process the packet...
            elif hip_packet.get_packet_type() == HIP.HIP_CLOSE_PACKET:
                logging.info("CLOSE packet");
                if hip_state.is_i1_sent() or hip_state.is_unassociated():
                    logging.debug("Dropping the packet...");
                # send close ack packet
                parameters       = hip_packet.get_parameters();

                echo_param       = None;
                signature_param  = None;
                mac_param        = None;

                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                        Utils.ipv6_bytes_to_hex_formatted(rhit));

                if not sv:
                    logging.debug("Not state exists. Skipping the packet...")
                    return [];

                keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
                if sv.is_responder:
                    hmac_alg  = HIT.get_responders_oga_id(rhit);
                    logging.debug("Responder's HMAC algorithm %d" % (hmac_alg));
                else:
                    hmac_alg  = HIT.get_responders_oga_id(ihit);
                    logging.debug("Responder's HMAC algorithm %d" % (hmac_alg));

                if Utils.is_hit_smaller(rhit, ihit):
                    cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit));

                logging.debug("Cipher algorithm %d " % (cipher_alg));
                logging.debug("HMAC algorithm %d" % (hmac_alg));
                # CLOSE packet incomming, IHIT - sender (Initiator), RHIT - own HIT (responder)
                if sv.is_responder:
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);
                else:
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
                hmac = HMACFactory.get(hmac_alg, hmac_key);

                for parameter in parameters:
                    if isinstance(parameter, HIP.EchoRequestSignedParameter):
                        logging.debug("Echo request signed parameter");
                        echo_param = parameter;
                        logging.debug(list(echo_param.get_byte_buffer()));
                    if isinstance(parameter, HIP.MACParameter):	
                        logging.debug("MAC parameter");
                        mac_param = parameter;
                    if isinstance(parameter, HIP.SignatureParameter):
                        logging.debug("Signature parameter");
                        signature_param = parameter;

                if not mac_param:
                    logging.debug("Missing MAC parameter");
                    return [];

                if not signature_param:
                    logging.debug("Missing signature parameter");
                    return [];
                
                hip_close_packet = HIP.ClosePacket();
                logging.debug("Sender's HIT %s" % (Utils.ipv6_bytes_to_hex_formatted(ihit)));
                logging.debug("Receiver's HIT %s" % (Utils.ipv6_bytes_to_hex_formatted(rhit)));
                hip_close_packet.set_senders_hit(ihit);
                hip_close_packet.set_receivers_hit(rhit);
                hip_close_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_close_packet.set_version(HIP.HIP_VERSION);
                hip_close_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                # Compute HMAC here
                buf = bytearray([]);
                buf += echo_param.get_byte_buffer();				

                original_length = hip_close_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_close_packet.set_length(int(packet_length / 8));
                buf = hip_close_packet.get_buffer() + buf;

                logging.debug("------------------------------------");
                logging.debug(list((buf)));
                logging.debug("------------------------------------");

                if hmac.digest(bytearray(buf)) != mac_param.get_hmac():
                    logging.critical("Invalid HMAC (CLOSE). Dropping the packet");
                    return [];
                logging.debug("HMAC OK");

                responders_public_key = self.pubkey_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                            Utils.ipv6_bytes_to_hex_formatted(rhit));

                if isinstance(responders_public_key, RSAPublicKey):
                    signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSAPublicKey):
                    signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSALowPublicKey):
                    signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());

                hip_close_packet = HIP.ClosePacket();
                hip_close_packet.set_senders_hit(ihit);
                hip_close_packet.set_receivers_hit(rhit);
                hip_close_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_close_packet.set_version(HIP.HIP_VERSION);
                hip_close_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                buf = bytearray([]);
                buf += echo_param.get_byte_buffer();
                buf += mac_param.get_byte_buffer();

                original_length = hip_close_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_close_packet.set_length(int(packet_length / 8));
                buf = hip_close_packet.get_buffer() + buf;

                if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
                    logging.critical("Invalid signature. Dropping the packet");
                    return [];
                else:
                    logging.debug("Signature is correct");

                #(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, rhit, ihit);
                if sv.is_responder:
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
                else:
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);
                hmac = HMACFactory.get(hmac_alg, hmac_key);

                hip_close_ack_packet = HIP.CloseAckPacket();
                hip_close_ack_packet.set_senders_hit(rhit);
                hip_close_ack_packet.set_receivers_hit(ihit);
                hip_close_ack_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_close_ack_packet.set_version(HIP.HIP_VERSION);
                hip_close_ack_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                echo_response_param = HIP.EchoResponseSignedParameter();
                echo_response_param.add_opaque_data(echo_param.get_opaque_data());
                hip_close_ack_packet.add_parameter(echo_response_param);

                mac_param = HIP.MACParameter();
                mac_param.set_hmac(hmac.digest(bytearray(hip_close_ack_packet.get_buffer())));
                hip_close_ack_packet.add_parameter(mac_param);

                if isinstance(self.privkey, RSAPrivateKey):
                    signature_alg = RSASHA256Signature(self.privkey.get_key_info());
                elif isinstance(self.privkey, ECDSAPrivateKey):
                    signature_alg = ECDSASHA384Signature(self.privkey.get_key_info());
                elif isinstance(self.privkey, ECDSALowPrivateKey):
                    signature_alg = ECDSASHA1Signature(self.privkey.get_key_info());

                signature = signature_alg.sign(bytearray(hip_close_ack_packet.get_buffer()));

                signature_param = HIP.SignatureParameter();
                signature_param.set_signature_algorithm(self.config["security"]["sig_alg"]);
                signature_param.set_signature(signature);

                hip_close_ack_packet.add_parameter(signature_param);

                # Swap the addresses
                temp = src;
                src = dst;
                dst = temp;

                # Create IPv4 packet
                ipv4_packet = IPv4.IPv4Packet();
                ipv4_packet.set_version(IPv4.IPV4_VERSION);
                ipv4_packet.set_destination_address(dst);
                ipv4_packet.set_source_address(src);
                ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
                ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

                # Calculate the checksum
                checksum = Utils.hip_ipv4_checksum(
                    src, 
                    dst, 
                    HIP.HIP_PROTOCOL, 
                    hip_close_ack_packet.get_length() * 8 + 8, 
                    hip_close_ack_packet.get_buffer());
                hip_close_ack_packet.set_checksum(checksum);
                ipv4_packet.set_payload(hip_close_ack_packet.get_buffer());
                # Send the packet
                dst_str = Utils.ipv4_bytes_to_string(dst);
                src_str = Utils.ipv4_bytes_to_string(src);
                
                logging.debug("Sending CLOSE ACK packet %s" % (dst_str));
                response.append((bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0)))
                if hip_state.is_r2_sent() or hip_state.is_established() or hip_state.is_i2_sent() or hip_state.is_closing():
                    hip_state.closed();
                    if Utils.is_hit_smaller(rhit, ihit):
                        sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                            Utils.ipv6_bytes_to_hex_formatted(ihit))
                    else:
                        sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                            Utils.ipv6_bytes_to_hex_formatted(rhit))
                    sv.closed_timeout = time.time() + self.config["general"]["UAL"] + 2*self.config["general"]["MSL"];
            elif hip_packet.get_packet_type == HIP.HIP_CLOSE_ACK_PACKET:
                logging.info("CLOSE ACK packet");
                if hip_state.is_r2_sent() or hip_state.is_established() or hip_state.is_i1_sent() or hip_state.is_i2_sent() or hip_state.is_unassociated() or hip_state.is_closing():
                    logging.debug("Dropping packet");
                    return [];
                
                parameters       = hip_packet.get_parameters();

                echo_param       = None;
                signature_param  = None;
                mac_param        = None;

                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                        Utils.ipv6_bytes_to_hex_formatted(rhit));

                if not sv:
                    logging.debug("Not state exists. Skipping the packet...")
                    return [];

                keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
                if sv.is_responder:
                    hmac_alg  = HIT.get_responders_oga_id(rhit);
                    logging.debug("Responder's HMAC algorithm %d" % (hmac_alg));
                else:
                    hmac_alg  = HIT.get_responders_oga_id(ihit);
                    logging.debug("Responder's HMAC algorithm %d" % (hmac_alg));

                if Utils.is_hit_smaller(rhit, ihit):
                    cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                        Utils.ipv6_bytes_to_hex_formatted(ihit));
                else:
                    cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(rhit));
                logging.debug("Cipher algorithm %d " % (cipher_alg));
                logging.debug("HMAC algorithm %d" % (hmac_alg));
                if sv.is_responder:
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);
                else:
                    (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
                hmac = HMACFactory.get(hmac_alg, hmac_key);

                for parameter in parameters:
                    if isinstance(parameter, HIP.EchoResponseSignedParameter):
                        logging.debug("Echo response signed parameter");
                        echo_param = parameter;
                        logging.debug(list(echo_param.get_byte_buffer()));
                    if isinstance(parameter, HIP.MACParameter):	
                        logging.debug("MAC parameter");
                        mac_param = parameter;
                    if isinstance(parameter, HIP.SignatureParameter):
                        logging.debug("Signature parameter");
                        signature_param = parameter;

                if not mac_param:
                    logging.debug("Missing MAC parameter");
                    return [];

                if not signature_param:
                    logging.debug("Missing signature parameter");
                    return [];
                
                hip_close_ack_packet = HIP.CloseAckPacket();
                logging.debug("Sender's HIT %s" % (Utils.ipv6_bytes_to_hex_formatted(ihit)));
                logging.debug("Receiver's HIT %s" % (Utils.ipv6_bytes_to_hex_formatted(rhit)));
                hip_close_ack_packet.set_senders_hit(ihit);
                hip_close_ack_packet.set_receivers_hit(rhit);
                hip_close_ack_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_close_ack_packet.set_version(HIP.HIP_VERSION);
                hip_close_ack_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                # Compute HMAC here
                buf = bytearray([]);
                buf += echo_param.get_byte_buffer();				

                original_length = hip_close_ack_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_close_ack_packet.set_length(int(packet_length / 8));
                buf = hip_close_ack_packet.get_buffer() + buf;

                logging.debug("------------------------------------");
                logging.debug(list((buf)));
                logging.debug("------------------------------------");

                if hmac.digest(bytearray(buf)) != mac_param.get_hmac():
                    logging.critical("Invalid HMAC (CLOSE ACK). Dropping the packet");
                    return [];
                logging.debug("HMAC OK");

                responders_public_key = self.pubkey_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                            Utils.ipv6_bytes_to_hex_formatted(rhit));

                if isinstance(responders_public_key, RSAPublicKey):
                    signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSAPublicKey):
                    signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
                elif isinstance(responders_public_key, ECDSALowPublicKey):
                    signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());

                hip_close_ack_packet = HIP.CloseAckPacket();
                hip_close_ack_packet.set_senders_hit(ihit);
                hip_close_ack_packet.set_receivers_hit(rhit);
                hip_close_ack_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_close_ack_packet.set_version(HIP.HIP_VERSION);
                hip_close_ack_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                buf = bytearray([]);
                buf += echo_param.get_byte_buffer();
                buf += mac_param.get_byte_buffer();

                original_length = hip_close_ack_packet.get_length();
                packet_length = original_length * 8 + len(buf);
                hip_close_ack_packet.set_length(int(packet_length / 8));
                buf = hip_close_ack_packet.get_buffer() + buf;

                if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
                    logging.critical("Invalid signature. Dropping the packet");
                    return [];
                else:
                    logging.debug("Signature is correct");

                if hip_state.is_closing() or hip_state.is_closed():
                    logging.debug("Moving to unassociated state...");
                    hip_state.unassociated();
            return response;
        except Exception as e:
            # We need more inteligent handling of exceptions here
            logging.critical("Exception occured. Dropping packet HIPv2.")
            logging.critical(e, exc_info=True);
            traceback.print_exc()
        return []

    def process_ip_sec_packet(self, packet):
        """
        This routine is responsible for reading IPSec packets
        from the raw socket
        """
        #logging.debug("Processing IPSec packet");

        try:
            #buf           = bytearray(ip_sec_socket.recv(2*MTU));
            ipv4_packet   = IPv4.IPv4Packet(packet);

            data          = ipv4_packet.get_payload();
            ip_sec_packet = IPSec.IPSecPacket(data);

            # IPv4 fields
            src           = ipv4_packet.get_source_address();
            dst           = ipv4_packet.get_destination_address();

            src_str       = Utils.ipv4_bytes_to_string(src);
            dst_str       = Utils.ipv4_bytes_to_string(dst);

            #logging.debug("Got packet from %s to %s of %d bytes" % (src_str, dst_str, len(buf)));
            # Get SA record and construct the ESP payload
            sa_record   = self.ip_sec_sa.get_record(src_str, dst_str);
            if not sa_record:
                return (None, None, None) 
            hmac_alg    = sa_record.get_hmac_alg();
            cipher      = sa_record.get_aes_alg();
            hmac_key    = sa_record.get_hmac_key();
            cipher_key  = sa_record.get_aes_key();
            ihit        = sa_record.get_src();
            rhit        = sa_record.get_dst();

            if Utils.is_hit_smaller(rhit, ihit):
                sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                    Utils.ipv6_bytes_to_hex_formatted(ihit));
            else:
                sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                    Utils.ipv6_bytes_to_hex_formatted(rhit));

            sv.data_timeout = time.time() + self.config["general"]["UAL"];
            """
            logging.debug(hexlify(ihit))
            logging.debug(hexlify(rhit))
            logging.debug("------------------- HMAC key IPSEC ------------------");
            logging.debug(hexlify(hmac_key));
            logging.debug("Cipher key IPSEC");
            logging.debug(hexlify(cipher_key));
            """

            icv         = ip_sec_packet.get_byte_buffer()[-hmac_alg.LENGTH:];

            #logging.debug("Calculating ICV over IPSec packet");
            #logging.debug(list(ip_sec_packet.get_byte_buffer())[:-hmac_alg.LENGTH]);

            """
            logging.debug("---------------------ICV--------------------")
            logging.debug(bytearray(icv))
            logging.debug("--------------------------------------------")
            """

            if icv != hmac_alg.digest(ip_sec_packet.get_byte_buffer()[:-hmac_alg.LENGTH]):
                logging.critical("Invalid ICV in IPSec packet");
                return  (None, None, None);

            padded_data = ip_sec_packet.get_payload()[:-hmac_alg.LENGTH];
            #logging.debug("Encrypted padded data");
            #logging.debug(padded_data);

            iv          = padded_data[:cipher.BLOCK_SIZE];
            
            #logging.debug("IV");
            #logging.debug(iv);

            padded_data = padded_data[cipher.BLOCK_SIZE:];

            #logging.debug("Padded data");
            #logging.debug(padded_data);

            decrypted_data = cipher.decrypt(cipher_key, bytearray(iv), bytearray(padded_data));

            #logging.debug("Decrypted padded data");
            #logging.debug(decrypted_data);

            frame  = IPSec.IPSecUtils.unpad(cipher.BLOCK_SIZE, decrypted_data);
            #next_header    = IPSec.IPSecUtils.get_next_header(decrypted_data);
            

            if Utils.is_hit_smaller(rhit, ihit):
                hip_state = self.hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                    Utils.ipv6_bytes_to_hex_formatted(ihit));
            else:
                hip_state = self.hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(rhit));
            if not hip_state:
                return (None, None, None);
            hip_state.established();
            #logging.debug("Sending IPv6 packet to %s" % (Utils.ipv6_bytes_to_hex_formatted(ihit)));
            #hip_tun.write(bytearray(ipv6_packet.get_buffer()));
            if ihit != self.own_hit:
                return (frame, rhit, ihit);
            else:
                return (frame, ihit, rhit);

        except Exception as e:
            logging.critical("Exception occured. Dropping IPSec packet.");
            logging.critical(e);
            traceback.print_exc();

    def process_l2_frame(self, frame, ihit, rhit, src_str):
        try:
            response = [];
            #logging.debug("Processing L2 frame")
            if Utils.is_hit_smaller(rhit, ihit):
                hip_state = self.hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
                    Utils.ipv6_bytes_to_hex_formatted(ihit));
            else:
                hip_state = self.hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(rhit));
            if hip_state.is_unassociated() or hip_state.is_closing() or hip_state.is_closed():
                #logging.debug("Unassociate state reached");
                #logging.debug("Starting HIP BEX %f" % (time.time()));
                #logging.info("Resolving %s to IPv4 address" % Utils.ipv6_bytes_to_hex_formatted(rhit));

                # Resolve the HIT code can be improved
                if not self.hit_resolver.resolve(Utils.ipv6_bytes_to_hex_formatted_resolver(rhit)):
                    #logging.critical("Cannot resolve HIT to IPv4 address");
                    return [];

                # Convert bytes to string representation of IPv6 address
                dst_str = self.hit_resolver.resolve(
                    Utils.ipv6_bytes_to_hex_formatted_resolver(rhit));
                dst = Math.int_to_bytes(
                    Utils.ipv4_to_int(dst_str));
                src = Math.int_to_bytes(
                    Utils.ipv4_to_int(src_str));

                st = time.time();
                # Construct the DH groups parameter
                dh_groups_param = HIP.DHGroupListParameter();
                dh_groups_param.add_groups(self.config["security"]["supported_DH_groups"]);

                # Create I1 packet
                hip_i1_packet = HIP.I1Packet();
                hip_i1_packet.set_senders_hit(ihit);
                hip_i1_packet.set_receivers_hit(rhit);
                hip_i1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                hip_i1_packet.set_version(HIP.HIP_VERSION);
                hip_i1_packet.add_parameter(dh_groups_param);

                # Compute the checksum of HIP packet
                checksum = Utils.hip_ipv4_checksum(
                    src, 
                    dst, 
                    HIP.HIP_PROTOCOL, 
                    hip_i1_packet.get_length() * 8 + 8, 
                    hip_i1_packet.get_buffer());
                hip_i1_packet.set_checksum(checksum);

                # Construct the IPv4 packet
                ipv4_packet = IPv4.IPv4Packet();
                ipv4_packet.set_version(IPv4.IPV4_VERSION);
                ipv4_packet.set_destination_address(dst);
                ipv4_packet.set_source_address(src);
                ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
                ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);
                ipv4_packet.set_payload(hip_i1_packet.get_buffer());

                # Send HIP I1 packet to destination
                logging.debug("Sending I1 packet to %s %f" % (dst_str, time.time() - st));
                #hip_socket.sendto(bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0));
                response.append((True, bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0)))
                # Transition to an I1-Sent state
                hip_state.i1_sent();

                
                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                        Utils.ipv6_bytes_to_hex_formatted(ihit))
                    if not sv:
                        self.state_variables.save(Utils.ipv6_bytes_to_hex_formatted(rhit),
                            Utils.ipv6_bytes_to_hex_formatted(ihit),
                            HIPState.StateVariables(hip_state.get_state(), ihit, rhit, src, dst));
                    else:
                        sv.state = hip_state.get_state()
                        sv.ihit = ihit;
                        sv.rhit = rhit;
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
                        Utils.ipv6_bytes_to_hex_formatted(ihit))
                    sv.is_responder = False;
                    sv.i1_timeout = time.time() + self.config["general"]["i1_timeout_s"];
                    sv.i1_retries += 1;
                else:
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                        Utils.ipv6_bytes_to_hex_formatted(rhit))
                    if not sv:
                        self.state_variables.save(Utils.ipv6_bytes_to_hex_formatted(ihit),
                            Utils.ipv6_bytes_to_hex_formatted(rhit),
                            HIPState.StateVariables(hip_state.get_state(), ihit, rhit, src, dst));
                    else:
                        sv.state = hip_state.get_state()
                        sv.ihit = ihit;
                        sv.rhit = rhit;
                    sv = self.state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
                        Utils.ipv6_bytes_to_hex_formatted(rhit))
                    sv.is_responder = False;
                    sv.i1_timeout = time.time() + self.config["general"]["i1_timeout_s"];
                    sv.i1_retries += 1;
            elif hip_state.is_established():
                #logging.debug("Sending IPSEC packet...")
                # IPv6 fields
                rhit_str    = Utils.ipv6_bytes_to_hex_formatted(rhit);
                ihit_str    = Utils.ipv6_bytes_to_hex_formatted(ihit);
                #next_header = packet.get_next_header();
                data        = frame.get_buffer();

                if Utils.is_hit_smaller(rhit, ihit):
                    sv = self.state_variables.get(rhit_str,
                        ihit_str);
                else:
                    sv = self.state_variables.get(ihit_str,
                        rhit_str);
                sv.data_timeout = time.time() + self.config["general"]["UAL"];

                # Get SA record and construct the ESP payload
                try:
                    sa_record  = self.ip_sec_sa.get_record(ihit_str, rhit_str);
                except:
                    sa_record  = self.ip_sec_sa.get_record(rhit_str, ihit_str);
                seq        = sa_record.get_sequence();
                spi        = sa_record.get_spi();
                hmac_alg   = sa_record.get_hmac_alg();
                cipher     = sa_record.get_aes_alg();
                hmac_key   = sa_record.get_hmac_key();
                cipher_key = sa_record.get_aes_key();
                src        = sa_record.get_src();
                dst        = sa_record.get_dst();
                iv         = Utils.generate_random(cipher.BLOCK_SIZE);
                sa_record.increment_sequence();
                """
                logging.debug("HMAC key L2 frame");
                logging.debug(hexlify(hmac_key));
                logging.debug("Cipher key L2 frame");
                logging.debug(hexlify(cipher_key));
                logging.debug("IV");
                logging.debug(hexlify(iv));
                """
                padded_data = IPSec.IPSecUtils.pad(cipher.BLOCK_SIZE, data, 0x0);
                #logging.debug("Length of the padded data %d" % (len(padded_data)));

                encrypted_data = cipher.encrypt(cipher_key, iv, padded_data);
                
                """
                logging.debug("Padded data");
                logging.debug(iv + list(encrypted_data));
                logging.debug(list(encrypted_data));

                logging.debug("Encrypted padded data");
                logging.debug(padded_data);
                """

                ip_sec_packet = IPSec.IPSecPacket();
                ip_sec_packet.set_spi(spi);
                ip_sec_packet.set_sequence(seq);
                ip_sec_packet.add_payload(iv + encrypted_data);

                #logging.debug("Calculating ICV over IPSec packet");
                #logging.debug(list(ip_sec_packet.get_byte_buffer()));

                icv = hmac_alg.digest(bytearray(ip_sec_packet.get_byte_buffer()));
                #logging.debug("---------------------ICV--------------------")
                #logging.debug(bytearray(icv))
                #logging.debug("--------------------------------------------")

                ip_sec_packet.add_payload(icv);

                # Send ESP packet to destination
                ipv4_packet = IPv4.IPv4Packet();
                ipv4_packet.set_version(IPv4.IPV4_VERSION);
                ipv4_packet.set_destination_address(dst);
                ipv4_packet.set_source_address(src);
                ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                ipv4_packet.set_protocol(IPSec.IPSEC_PROTOCOL);
                ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);
                ipv4_packet.set_payload(ip_sec_packet.get_byte_buffer());

                #logging.debug("Sending IPSEC packet to %s %d bytes" % (Utils.ipv4_bytes_to_string(dst), len(ipv4_packet.get_buffer())));

                #ip_sec_socket.sendto(
                #    bytearray(ipv4_packet.get_buffer()), 
                #    (Utils.ipv4_bytes_to_string(dst), 0));
                response.append((False, bytearray(ipv4_packet.get_buffer()), (Utils.ipv4_bytes_to_string(dst), 0)))
            else:
                pass
                #logging.debug("Unknown state reached.... %s " % (hip_state));
            return response;
        except Exception as e:
            logging.critical("Exception occured while processing packet from TUN interface. Dropping the packet.");
            logging.critical(e, exc_info=True);
            traceback.print_exc()
        return [];

    def exit_handler(self):
        response = []
        for key in self.state_variables.keys():
            logging.debug("Sending close packet....");
            sv = self.state_variables.get_by_key(key);
            if Utils.is_hit_smaller(sv.rhit, sv.ihit):
                hip_state = self.hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
                    Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
            else:
                hip_state = self.hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(sv.rhit));

            if hip_state.is_unassociated():
                return [];

            #if Utils.is_hit_smaller(sv.rhit, sv.ihit):
            #    keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
            #        Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
            #else:
            #    keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
            #        Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
            #if sv.is_responder:
        
            keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
            #if not keymat:
            #    logging.debug("------ GETING KEYMAT IN CLOSE ------- %s %s %d" % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit), Utils.ipv6_bytes_to_hex_formatted(sv.rhit), sv.is_responder))
            #    logging.debug("++++++++++++++++++++++++++++ ERROR INVALID KEYING MATERIAL CLOSE ++++++++++++++++++++++++++++")
            #    keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
            #        Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
            logging.debug("Responder's HIT %s" % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
            logging.debug("Initiator's HIT %s" % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
            hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
            logging.debug("Responder's HMAC algorithm %d " % (hmac_alg))
            #if sv.is_responder:
            #	logging.debug("Host is Responder....")
            #	
            #	logging.debug("Responder's HMAC algorithm %d " % (hmac_alg))
            #else:
            #	hmac_alg  = HIT.get_responders_oga_id(sv.ihit);
            #	logging.debug("Responder's HMAC algorithm %d " % (hmac_alg))

            if Utils.is_hit_smaller(sv.rhit, sv.ihit):
                #hmac_alg  = HIT.get_responders_oga_id(sv.ihit);
                cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
                    Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
            else:
                #hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
                cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
            # OUTGOING
            if sv.is_responder:
                (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
            else:
                (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);
            hmac = HMACFactory.get(hmac_alg, hmac_key);

            hip_close_packet = HIP.ClosePacket();

            if sv.is_responder:
                hip_close_packet.set_senders_hit(sv.rhit);
                hip_close_packet.set_receivers_hit(sv.ihit);
            else:
                hip_close_packet.set_senders_hit(sv.ihit);
                hip_close_packet.set_receivers_hit(sv.rhit);

            hip_close_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
            hip_close_packet.set_version(HIP.HIP_VERSION);
            hip_close_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

            echo_param = HIP.EchoRequestSignedParameter();
            echo_param.add_opaque_data(Utils.generate_random(4));
            hip_close_packet.add_parameter(echo_param);

            mac_param = HIP.MACParameter();
            mac_param.set_hmac(hmac.digest(bytearray(hip_close_packet.get_buffer())));
            hip_close_packet.add_parameter(mac_param);

            #signature_alg = RSASHA256Signature(privkey.get_key_info());
            if isinstance(self.privkey, RSAPrivateKey):
                signature_alg = RSASHA256Signature(self.privkey.get_key_info());
            elif isinstance(self.privkey, ECDSAPrivateKey):
                signature_alg = ECDSASHA384Signature(self.privkey.get_key_info());
            elif isinstance(self.privkey, ECDSALowPrivateKey):
                signature_alg = ECDSASHA1Signature(self.privkey.get_key_info());
            
            signature = signature_alg.sign(bytearray(hip_close_packet.get_buffer()));

            signature_param = HIP.SignatureParameter();
            signature_param.set_signature_algorithm(self.config["security"]["sig_alg"]);
            signature_param.set_signature(signature);

            hip_close_packet.add_parameter(signature_param);

            # Create IPv4 packet
            ipv4_packet = IPv4.IPv4Packet();
            ipv4_packet.set_version(IPv4.IPV4_VERSION);
            ipv4_packet.set_destination_address(sv.dst);
            ipv4_packet.set_source_address(sv.src);
            ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
            ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
            ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

            # Calculate the checksum
            checksum = Utils.hip_ipv4_checksum(
                sv.dst, 
                sv.src, 
                HIP.HIP_PROTOCOL, 
                hip_close_packet.get_length() * 8 + 8, 
                hip_close_packet.get_buffer());
            hip_close_packet.set_checksum(checksum);
            ipv4_packet.set_payload(hip_close_packet.get_buffer());
            # Send the packet
            dst_str = Utils.ipv4_bytes_to_string(sv.dst);
            src_str = Utils.ipv4_bytes_to_string(sv.src);
                    
            logging.debug("Sending CLOSE PACKET packet %s" % (dst_str));
            response.append((bytearray(ipv4_packet.get_buffer()), (dst_str, 0)))
            #hip_socket.sendto(
            #    bytearray(ipv4_packet.get_buffer()), 
            #    (dst_str, 0));
        return response;

    def maintenance(self):
        response = []
        for key in self.state_variables.keys():
            sv = self.state_variables.get_by_key(key);

            if Utils.is_hit_smaller(sv.rhit, sv.ihit):
                hip_state = self.hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
                    Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
            else:
                hip_state = self.hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                    Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
            if hip_state.is_established():
                if time.time() >= sv.data_timeout:
                    keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
                    logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
                    logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                    hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
                    logging.debug("Responders's HMAC algorithm %d" % (hmac_alg))                    
                    if Utils.is_hit_smaller(sv.rhit, sv.ihit):
                        cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
                            Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
                        #hmac_alg  = HIT.get_responders_oga_id(sv.ihit);
                    else:
                        cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                            Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
                    if sv.is_responder:
                        (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
                    else:
                        (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);

                    hmac = HMACFactory.get(hmac_alg, hmac_key);
                    logging.debug("HMAC algorithm %d" % (hmac_alg));
                    logging.debug(list(hmac_key));

                    hip_close_packet = HIP.ClosePacket();
                    if sv.is_responder:
                        hip_close_packet.set_senders_hit(sv.rhit);
                        hip_close_packet.set_receivers_hit(sv.ihit);
                    else:
                        hip_close_packet.set_senders_hit(sv.ihit);
                        hip_close_packet.set_receivers_hit(sv.rhit);
                    hip_close_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                    hip_close_packet.set_version(HIP.HIP_VERSION);
                    hip_close_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                    echo_param = HIP.EchoRequestSignedParameter();
                    echo_param.add_opaque_data(Utils.generate_random(4));
                    hip_close_packet.add_parameter(echo_param);

                    mac_param = HIP.MACParameter();
                    logging.debug("------------------------------");
                    logging.debug(list(hip_close_packet.get_buffer()));
                    logging.debug("------------------------------");
                    mac_param.set_hmac(hmac.digest(bytearray(hip_close_packet.get_buffer())));
                    hip_close_packet.add_parameter(mac_param);

                    if isinstance(self.privkey, RSAPrivateKey):
                        signature_alg = RSASHA256Signature(self.privkey.get_key_info());
                    elif isinstance(self.privkey, ECDSAPrivateKey):
                        signature_alg = ECDSASHA384Signature(self.privkey.get_key_info());
                    elif isinstance(self.privkey, ECDSALowPrivateKey):
                        signature_alg = ECDSASHA1Signature(self.privkey.get_key_info());
                    
                    signature = signature_alg.sign(bytearray(hip_close_packet.get_buffer()));

                    signature_param = HIP.SignatureParameter();
                    signature_param.set_signature_algorithm(self.config["security"]["sig_alg"]);
                    signature_param.set_signature(signature);

                    hip_close_packet.add_parameter(signature_param);

                    # Create IPv4 packet
                    ipv4_packet = IPv4.IPv4Packet();
                    ipv4_packet.set_version(IPv4.IPV4_VERSION);
                    ipv4_packet.set_destination_address(sv.dst);
                    ipv4_packet.set_source_address(sv.src);
                    ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                    ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
                    ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

                    # Calculate the checksum
                    checksum = Utils.hip_ipv4_checksum(
                        sv.dst, 
                        sv.src, 
                        HIP.HIP_PROTOCOL, 
                        hip_close_packet.get_length() * 8 + 8, 
                        hip_close_packet.get_buffer());
                    hip_close_packet.set_checksum(checksum);
                    ipv4_packet.set_payload(hip_close_packet.get_buffer());
                    # Send the packet
                    dst_str = Utils.ipv4_bytes_to_string(sv.dst);
                    src_str = Utils.ipv4_bytes_to_string(sv.src);
                    logging.debug("Sending CLOSE PACKET packet %s" % (dst_str));
                    response.append((bytearray(ipv4_packet.get_buffer()), (dst_str, 0)))
                    hip_state.closing();
                    sv.closing_timeout = time.time() + self.config["general"]["UAL"] + self.config["general"]["MSL"];
                if time.time() >= sv.update_timeout:
                    sv.update_timeout = time.time() + self.config["general"]["update_timeout_s"];
                    keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
                    logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
                    logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                    hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
                    logging.debug("Using Responders's HMAC algorithm %d" % (hmac_alg))

                    if Utils.is_hit_smaller(sv.rhit, sv.ihit):
                        cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
                            Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
                    else:
                        cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                            Utils.ipv6_bytes_to_hex_formatted(sv.rhit));

                    # OUTGOING
                    if sv.is_responder:
                        (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
                    else:
                        (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);
                    
                    hmac = HMACFactory.get(hmac_alg, hmac_key);

                    hip_update_packet = HIP.UpdatePacket();
                    if sv.is_responder:
                        hip_update_packet.set_senders_hit(sv.rhit);
                        hip_update_packet.set_receivers_hit(sv.ihit);
                        logging.debug("Source HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
                        logging.debug("Destination HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                    else:
                        hip_update_packet.set_senders_hit(sv.ihit);
                        hip_update_packet.set_receivers_hit(sv.rhit);
                        logging.debug("Source HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                        logging.debug("Destination HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
                    hip_update_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                    hip_update_packet.set_version(HIP.HIP_VERSION);
                    hip_update_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                    sv.update_seq += 1;
                    seq_param = HIP.SequenceParameter();
                    seq_param.set_id(sv.update_seq);
                    hip_update_packet.add_parameter(seq_param);

                    mac_param = HIP.MACParameter();
                    mac_param.set_hmac(hmac.digest(bytearray(hip_update_packet.get_buffer())));
                    hip_update_packet.add_parameter(mac_param);

                    if isinstance(self.privkey, RSAPrivateKey):
                        signature_alg = RSASHA256Signature(self.privkey.get_key_info());
                    elif isinstance(self.privkey, ECDSAPrivateKey):
                        signature_alg = ECDSASHA384Signature(self.privkey.get_key_info());
                    elif isinstance(self.privkey, ECDSALowPrivateKey):
                        signature_alg = ECDSASHA1Signature(self.privkey.get_key_info());
                    signature = signature_alg.sign(bytearray(hip_update_packet.get_buffer()));

                    signature_param = HIP.SignatureParameter();
                    signature_param.set_signature_algorithm(self.config["security"]["sig_alg"]);
                    signature_param.set_signature(signature);

                    hip_update_packet.add_parameter(signature_param);

                    # Create IPv4 packet
                    ipv4_packet = IPv4.IPv4Packet();
                    ipv4_packet.set_version(IPv4.IPV4_VERSION);
                    ipv4_packet.set_destination_address(sv.dst);
                    ipv4_packet.set_source_address(sv.src);
                    ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                    ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
                    ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

                    # Calculate the checksum
                    checksum = Utils.hip_ipv4_checksum(
                        sv.dst, 
                        sv.src, 
                        HIP.HIP_PROTOCOL, 
                        hip_update_packet.get_length() * 8 + 8, 
                        hip_update_packet.get_buffer());
                    hip_update_packet.set_checksum(checksum);
                    ipv4_packet.set_payload(hip_update_packet.get_buffer());
                    # Send the packet
                    dst_str = Utils.ipv4_bytes_to_string(sv.dst);
                    src_str = Utils.ipv4_bytes_to_string(sv.src);
                    
                    logging.debug("Sending UPDATE PACKET packet %s" % (dst_str));
                    response.append((bytearray(ipv4_packet.get_buffer()), (dst_str, 0)))
            elif hip_state.is_i1_sent():
                if time.time() >= sv.i1_timeout:
                    sv.i1_timeout = time.time() + self.config["general"]["i1_timeout_s"];
                    dh_groups_param = HIP.DHGroupListParameter();
                    dh_groups_param.add_groups(self.config["security"]["supported_DH_groups"]);
                    # Create I1 packet
                    hip_i1_packet = HIP.I1Packet();
                    
                    if sv.is_responder:
                        hip_i1_packet.set_senders_hit(sv.rhit);
                        hip_i1_packet.set_receivers_hit(sv.ihit);
                        #sv.ihit = sv.rhit
                        #sv.rhit = sv.ihit
                        logging.debug("Source HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
                        logging.debug("Destination HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                    else:
                        hip_i1_packet.set_senders_hit(sv.ihit);
                        hip_i1_packet.set_receivers_hit(sv.rhit);
                        logging.debug("Source HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                        logging.debug("Destination HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))

                    #sv.is_responder = False;
                    hip_i1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                    hip_i1_packet.set_version(HIP.HIP_VERSION);
                    hip_i1_packet.add_parameter(dh_groups_param);

                    # Compute the checksum of HIP packet
                    checksum = Utils.hip_ipv4_checksum(
                        sv.src, 
                        sv.dst, 
                        HIP.HIP_PROTOCOL, 
                        hip_i1_packet.get_length() * 8 + 8, 
                        hip_i1_packet.get_buffer());
                    hip_i1_packet.set_checksum(checksum);

                    dst_str = Utils.ipv4_bytes_to_string(sv.dst);
                    src_str = Utils.ipv4_bytes_to_string(sv.src);

                    # Construct the IPv4 packet
                    ipv4_packet = IPv4.IPv4Packet();
                    ipv4_packet.set_version(IPv4.IPV4_VERSION);
                    ipv4_packet.set_destination_address(sv.dst);
                    ipv4_packet.set_source_address(sv.src);
                    ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                    ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
                    ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);
                    ipv4_packet.set_payload(hip_i1_packet.get_buffer());

                    # Send HIP I1 packet to destination
                    logging.debug("Re-sending I1 packet to %s" % (dst_str));
                    logging.debug("Re-sending I1 packet from %s" % (src_str));
                    logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
                    logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                    logging.debug("I2 packet buffer------------")
                    logging.debug(ipv4_packet.get_buffer())

                    #hip_socket.sendto(bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0))
                    response.append((bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0)))
                    
                    if sv.i1_retries > self.config["general"]["i1_retries"]:
                        hip_state.failed();
                        sv.failed_timeout = time.time() + self.config["general"]["failed_timeout"];
                    sv.i1_retries += 1;
            elif hip_state.is_i2_sent():
                if sv.i2_timeout <= time.time():
                    dst_str = Utils.ipv4_bytes_to_string(sv.dst);
                    src_str = Utils.ipv4_bytes_to_string(sv.src);
                    # Send HIP I2 packet to destination
                    logging.debug("Re-sending I2 packet to %s" % (dst_str));
                    logging.debug("Re-sending I2 packet from %s" % (src_str));
                    logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
                    logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                    response.append((bytearray(sv.i2_packet.get_buffer()), (dst_str.strip(), 0)))
                    
                    #if sv.is_responder:
                    #sv.ihit = sv.rhit
                    #sv.rhit = sv.ihit

                    #sv.is_responder = False;

                    if sv.i2_retries > self.config["general"]["i2_retries"]:
                        hip_state.failed();
                        sv.failed_timeout = time.time() + self.config["general"]["failed_timeout"];
                        return response;
                    sv.i2_timeout = time.time() + self.config["general"]["i2_timeout_s"];
                    sv.i2_retries += 1;
            elif hip_state.is_r2_sent():
                if sv.ec_complete_timeout <= time.time():
                    logging.debug("EC timeout. Moving to established state...");
                    hip_state.established();
            elif hip_state.is_closing():
                if sv.closing_timeout <= time.time():
                    keymat = self.keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                        Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
                    logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
                    logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                    hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
                    logging.debug("Responders's HMAC algorithm %d" % (hmac_alg))
                    if Utils.is_hit_smaller(sv.rhit, sv.ihit):
                        cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
                            Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
                    else:
                        cipher_alg = self.cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
                            Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
                    # OUTGOING
                    if sv.is_responder:
                        (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
                    else:
                        (aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);

                    logging.debug("HMAC algorithm %d" % (hmac_alg));
                    hmac = HMACFactory.get(hmac_alg, hmac_key);
                    
                    hip_close_packet = HIP.ClosePacket();

                    if sv.is_responder:
                        hip_close_packet.set_senders_hit(sv.rhit);
                        hip_close_packet.set_receivers_hit(sv.ihit);
                        logging.debug("Source HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
                        logging.debug("Destination HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                    else:
                        hip_close_packet.set_senders_hit(sv.ihit);
                        hip_close_packet.set_receivers_hit(sv.rhit);
                        logging.debug("Source HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
                        logging.debug("Destination HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
                    hip_close_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
                    hip_close_packet.set_version(HIP.HIP_VERSION);
                    hip_close_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

                    echo_param = HIP.EchoRequestSignedParameter();
                    echo_param.add_opaque_data(Utils.generate_random(4));
                    hip_close_packet.add_parameter(echo_param);

                    mac_param = HIP.MACParameter();
                    mac_param.set_hmac(hmac.digest(bytearray(hip_close_packet.get_buffer())));
                    hip_close_packet.add_parameter(mac_param);

                    if isinstance(self.privkey, RSAPrivateKey):
                        signature_alg = RSASHA256Signature(self.privkey.get_key_info());
                    elif isinstance(self.privkey, ECDSAPrivateKey):
                        signature_alg = ECDSASHA384Signature(self.privkey.get_key_info());
                    elif isinstance(self.privkey, ECDSALowPrivateKey):
                        signature_alg = ECDSASHA1Signature(self.privkey.get_key_info());
                    
                    signature = signature_alg.sign(bytearray(hip_close_packet.get_buffer()));

                    signature_param = HIP.SignatureParameter();
                    signature_param.set_signature_algorithm(self.config["security"]["sig_alg"]);
                    signature_param.set_signature(signature);

                    hip_close_packet.add_parameter(signature_param);

                    # Create IPv4 packet
                    ipv4_packet = IPv4.IPv4Packet();
                    ipv4_packet.set_version(IPv4.IPV4_VERSION);
                    ipv4_packet.set_destination_address(sv.dst);
                    ipv4_packet.set_source_address(sv.src);
                    ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
                    ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
                    ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

                    # Calculate the checksum
                    checksum = Utils.hip_ipv4_checksum(
                        sv.dst, 
                        sv.src, 
                        HIP.HIP_PROTOCOL, 
                        hip_close_packet.get_length() * 8 + 8, 
                        hip_close_packet.get_buffer());
                    hip_close_packet.set_checksum(checksum);
                    ipv4_packet.set_payload(hip_close_packet.get_buffer());
                    # Send the packet
                    dst_str = Utils.ipv4_bytes_to_string(sv.dst);
                    src_str = Utils.ipv4_bytes_to_string(sv.src);
                    logging.debug("Sending CLOSE PACKET packet %s" % (dst_str));
                    response.append((bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0)))
                else:
                    logging.debug("Transitioning to UNASSOCIATED state....")
                    hip_state.unassociated();
            elif hip_state.is_closed():
                if sv.closed_timeout <= time.time():
                    logging.debug("Transitioning to UNASSOCIATED state....")
                    hip_state.unassociated();
            elif hip_state.is_failed():
                if sv.failed_timeout <= time.time():
                    logging.debug("Transitioning to UNASSOCIATED state...");
                    hip_state.unassociated();
        return response


