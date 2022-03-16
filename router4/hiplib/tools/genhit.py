#!/usr/bin/python3

# Copyright (C) 2022 strangebit

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
__copyright__ = "Copyright 2022, stangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@gmail.com"
__status__ = "development"

import sys

sys.path.append('.')

# Configuration
from hiplib.config import config
# Math functions
from math import ceil, floor
# System
import sys
# HIT
from hiplib.utils.hit import HIT
from hiplib.utils.hi import RSAHostID, ECDSAHostID, ECDSALowHostID
from hiplib.utils.di import DIFactory
# Utilities
from hiplib.utils.misc import Utils, Math
# Crypto
from hiplib.crypto import factory
from hiplib.crypto.asymmetric import RSAPublicKey, RSAPrivateKey, ECDSAPublicKey, ECDSAPrivateKey, RSASHA256Signature, ECDSALowPublicKey, ECDSALowPrivateKey, ECDSASHA384Signature, ECDSASHA1Signature
from hiplib.crypto.factory import HMACFactory, SymmetricCiphersFactory, ESPTransformFactory
# Utilities
from hiplib.utils.misc import Utils

class HITGenerator():
    def __init__(self, config):
        self.config = config;
        self.pubkey       = None;
        self.hi           = None;
        self.ipv6_address = None;
        self.own_hit      = None;

    def generateHIT(self):
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
            self.hi = ECDSAHostID(self.pubkey.get_curve_id(), self.pubkey.get_x(), self.pubkey.get_y());
            self.ipv6_address = HIT.get_hex_formated(self.hi.to_byte_array(), HIT.SHA384_OGA);
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
        print("HIT:")
        print(self.ipv6_address)

gen = HITGenerator(config.config)
gen.generateHIT()
