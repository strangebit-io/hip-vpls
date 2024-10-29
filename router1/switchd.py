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
__copyright__ = "Copyright 2022, strangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@gmail.com"
__status__ = "development"

# Import the needed libraries
# OS library
import os
# Stacktrace
import traceback
# Sockets
import socket
# Threading
import threading
# Logging
import logging
from logging.handlers import RotatingFileHandler
# Timing
import time
# Math functions
from math import ceil, floor
# System
import sys
# Exit handler
import atexit
# Timing 
from time import sleep
from time import time

# Hex
from binascii import hexlify

# Import HIP library
from hiplib import hlib

# Utilities
from hiplib.utils import misc

# Crypto stuff
from hiplib.crypto import digest

from hiplib.hlib import HIPLib

# HIP related packets
from hiplib.packets import HIP
# IPSec packets
from hiplib.packets import IPSec
# IPv6 packets
from hiplib.packets import IPv6
# IPv4 packets 
from hiplib.packets import IPv4
# Ethernet frame
from hiplib.packets import Ethernet
# Controller packets
from hiplib.packets import Controller
# Configuration
from hiplib.config import config as hip_config
# Import switch FIB
from switchfabric import FIB

# Network stuff
import socket
import ssl

# HIP controller lock
hip_config_socket_lock = threading.Lock()


# Copy routines
import copy

# Configure logging to console and file
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("hipls.log")#,
        #logging.StreamHandler(sys.stdout)
    ]
);

# HIP configuration 
hiplib = HIPLib(hip_config.config);

hip_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, HIP.HIP_PROTOCOL);
hip_socket.bind(("0.0.0.0", HIP.HIP_PROTOCOL));
# We will need to perform manual fragmentation
hip_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);
logging.info("Initializing IPSec socket");
ip_sec_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPSec.IPSEC_PROTOCOL);
#ip_sec_socket.bind(("0.0.0.0", IPSec.IPSEC_PROTOCOL));
ip_sec_socket.bind((hip_config.config["switch"]["source_ip"], IPSec.IPSEC_PROTOCOL))

# We will need to perform manual fragmentation
ip_sec_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);
# Open raw ethernet socket and bind it to the interface
ETH_P_ALL = 3
ether_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL));
ether_socket.bind((hip_config.config["switch"]["l2interface"], 0))

# Initialize FIB
fib = FIB(hip_config.config["switch"]["mesh"])


def onclose():
    packets = hiplib.exit_handler()
    for (packet, dest) in packets:
        hip_socket.sendto(packet, dest)


def hip_loop():
    while True:
        try:
            packet = bytearray(hip_socket.recv(1518))
            logging.debug("Got HIP packet on the interface")
            packets = hiplib.process_hip_packet(packet);
            for (packet, dest) in packets:
                hip_socket.sendto(packet, dest)
        except Exception as e:
            logging.debug("Exception occured while processing HIP packet")
            logging.debug(e)
            logging.debug(traceback.format_exc())

def ip_sec_loop():
    while True:
        try:
            es = time()
            s = time()
            packet = bytearray(ip_sec_socket.recv(1518));
            e = time()
            #logging.info("IPSEC recv time %f " % (e-s))
            s = time()
            (frame, src, dst) = hiplib.process_ip_sec_packet(packet)
            e = time()
            #logging.info("IPSEC process time %f " % (e-s))
            if not frame:
                continue;
            s = time()
            ether_socket.send(frame);
            e = time()
            #logging.info("L2 send time %f " % (e-s))
            frame = Ethernet.EthernetFrame(frame);
            fib.set_next_hop(frame.get_source(), src, dst);
            #logging.debug("Got frame in IPSec loop sending to L2 %s %s....", hexlify(frame.get_source()), hexlify(frame.get_destination()))
            ee = time()
            #logging.info("Total time to process the IPSEC packet %f" % (ee - es))
        except Exception as e:
            logging.debug("Exception occured while processing IPSEC packet")
            logging.critical(e)

def ether_loop():
    while True:
        try:
            s = time()
            buf = bytearray(ether_socket.recv(1518));
            e = time()
            #logging.info("Ethernet recv time %f " % (e-s))
            frame = Ethernet.EthernetFrame(buf);
            dst_mac = frame.get_destination();
            src_mac = frame.get_source();

            #logging.debug("Got data on Ethernet link L2 %s %s..." % (hexlify(src_mac), hexlify(dst_mac)))

            #logging.debug(hexlify(src_mac))
            #logging.debug(hexlify(dst_mac))

            #logging.debug("----------------------------------")
            es = time()
            
            mesh = fib.get_next_hop(dst_mac);
            for (ihit, rhit) in mesh:
                s = time()
                packets = hiplib.process_l2_frame(frame, ihit, rhit, hip_config.config["switch"]["source_ip"]);
                e = time()
                #logging.info("L2 process time %f " % (e-s))
                for (hip, packet, dest) in packets:
                    #logging.debug("Sending L2 frame to: %s %s" % (hexlify(ihit), hexlify(rhit)))
                    if not hip:
                        s = time()
                        ip_sec_socket.sendto(packet, dest)
                        e = time()
                        #logging.info("IPSEC send time %f " % (e-s))
                    else:
                        hip_socket.sendto(packet, dest)
            ee = time()
            #logging.info("Total time to process Ethernet frame %f" % (ee-es))
        except Exception as e:
           logging.debug("Exception occured while processing L2 frame")
           logging.debug(e)


# Register exit handler
atexit.register(onclose);

hip_th_loop = threading.Thread(target = hip_loop, args = (), daemon = True);
ip_sec_th_loop = threading.Thread(target = ip_sec_loop, args = (), daemon = True);
ether_if_th_loop = threading.Thread(target = ether_loop, args = (), daemon = True);

logging.info("Starting the switchd");

hip_th_loop.start();
ip_sec_th_loop.start();
ether_if_th_loop.start();

def run_switch():
    while True:
        try:
            packets = hiplib.maintenance();
            for (packet, dest) in packets:
                hip_socket.sendto(packet, dest)
            logging.debug("...Periodic cleaning task...")
            sleep(1);
        except Exception as e:
            logging.critical("Exception occured while processing HIP packets in maintenance loop")
            logging.critical(e);
            sleep(1)

run_switch()
