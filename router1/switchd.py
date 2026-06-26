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
from time import perf_counter

# Data-plane performance counters
from hiplib.utils import perfstats

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
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("hipls.log")#,
        #logging.StreamHandler(sys.stdout)
    ]
);

# If configured, run the data plane as separate processes (to escape the GIL)
# and never set up the in-process threaded data plane below. Default is
# "threads" which keeps the original behaviour unchanged.
if hip_config.config["switch"].get("dataplane_mode", "threads") == "processes":
    from hiplib import dataplane_mp
    dataplane_mp.run();
    sys.exit(0);

# Kernel data-plane mode: the HIP control plane (BEX) stays in Python but the
# data plane (encryption, L2 encapsulation, forwarding) is handed to the Linux
# kernel via a gretap bridge protected by XFRM ESP. No Python L2/IPSec loops.
if hip_config.config["switch"].get("dataplane_mode", "threads") == "kernel":
    from hiplib.network import xfrm
    from hiplib.utils.misc import Utils

    hiplib = HIPLib(hip_config.config);

    hip_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, HIP.HIP_PROTOCOL);
    hip_socket.bind(("0.0.0.0", HIP.HIP_PROTOCOL));
    hip_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);

    # Resolve mesh peers and the provider endpoints from config + hosts file.
    fib = FIB(hip_config.config["switch"]["mesh"]);
    own_hit     = hiplib.get_own_hit();
    local_ip    = hip_config.config["switch"]["source_ip"];
    l2interface = hip_config.config["switch"]["l2interface"];
    bridge      = hip_config.config["switch"].get("bridge", "br0");
    gretap_prefix = hip_config.config["switch"].get("gretap_prefix", "hvpls");

    _slog = logging.getLogger("hipvpls");
    _slog.setLevel(logging.INFO);
    _slog.info("---------------- Kernel data-plane next-hops ----------------");
    _slog.info("  own HIT=%s local provider IP=%s l2if=%s bridge=%s",
        Utils.ipv6_bytes_to_hex_formatted(own_hit), local_ip, l2interface, bridge);

    # Build, from the mesh + hosts config files: the BEX peer list (one HIP
    # association per peer) and the set of remote provider IPs (one isolated
    # pseudowire per peer). Adding a router => add lines to mesh + hosts; the
    # data plane scales itself, nothing here is hardcoded to a peer count.
    peers = [];
    peer_ips = [];
    seen_ips = set();
    for (ihit, rhit) in fib.fib_broadcast:
        peer = rhit if bytes(ihit) == bytes(own_hit) else ihit;
        peers.append((own_hit, peer));
        rip = hiplib.hit_resolver.resolve(Utils.ipv6_bytes_to_hex_formatted_resolver(peer));
        rip = rip.strip() if rip else None;
        _slog.info("  next-hop tunnel: peer HIT=%s -> provider IP=%s",
            Utils.ipv6_bytes_to_hex_formatted(peer), (rip if rip else "UNRESOLVED"));
        if rip and rip not in seen_ips:
            seen_ips.add(rip);
            peer_ips.append(rip);

    if peer_ips:
        xfrm.setup_l2_transport(l2interface, bridge, local_ip, peer_ips, gretap_prefix);
    else:
        logging.critical("Could not resolve any remote provider IP; L2 transport not set up");

    def onclose_kernel():
        try:
            packets = hiplib.exit_handler();
            for (packet, dest) in packets:
                hip_socket.sendto(packet, dest);
        except Exception:
            pass;
        xfrm.teardown(bridge, peer_ips, gretap_prefix, local_ip);
    atexit.register(onclose_kernel);

    def hip_loop_kernel():
        while True:
            try:
                packet = bytearray(hip_socket.recv(1518));
                packets = hiplib.process_hip_packet(packet);
                for (packet, dest) in packets:
                    hip_socket.sendto(packet, dest);
            except Exception as e:
                logging.debug("Exception while processing HIP packet: %s", e);

    th = threading.Thread(target = hip_loop_kernel, args = (), daemon = True);
    th.start();
    logging.info("Starting switchd in KERNEL data-plane mode");

    while True:
        try:
            packets = hiplib.maintenance();
            for (packet, dest) in packets:
                hip_socket.sendto(packet, dest);
            # Proactively (re)establish each mesh tunnel; the kernel handles the
            # data path once an association is ESTABLISHED (SAs installed in BEX).
            for (ihit, rhit) in peers:
                for (packet, dest) in hiplib.initiate_bex(ihit, rhit):
                    hip_socket.sendto(packet, dest);
            # Keep established associations pinned (avoid idle-close / rekey,
            # which would desync the kernel SAs).
            hiplib.refresh_kernel_timers();
            sleep(1);
        except Exception as e:
            logging.critical("Exception in kernel maintenance loop: %s", e);
            sleep(1);
    sys.exit(0);

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
            t0 = perf_counter()
            packet = bytearray(ip_sec_socket.recv(1518));
            t1 = perf_counter()
            perfstats.record("ipsec_recv", t1 - t0)
            (frame, src, dst) = hiplib.process_ip_sec_packet(packet)
            t2 = perf_counter()
            perfstats.record("ipsec_process", t2 - t1)
            if not frame:
                continue;
            ether_socket.send(frame);
            t3 = perf_counter()
            perfstats.record("eth_send", t3 - t2)
            perfstats.incr_bytes("rx_bytes", len(frame))
            frame = Ethernet.EthernetFrame(frame);
            fib.set_next_hop(frame.get_source(), src, dst);
            #logging.debug("Got frame in IPSec loop sending to L2 %s %s....", hexlify(frame.get_source()), hexlify(frame.get_destination()))
        except Exception as e:
            logging.debug("Exception occured while processing IPSEC packet")
            logging.critical(e)

def ether_loop():
    while True:
        try:
            t0 = perf_counter()
            buf = bytearray(ether_socket.recv(1518));
            t1 = perf_counter()
            perfstats.record("eth_recv", t1 - t0)
            frame = Ethernet.EthernetFrame(buf);
            dst_mac = frame.get_destination();
            src_mac = frame.get_source();

            mesh = fib.get_next_hop(dst_mac);
            for (ihit, rhit) in mesh:
                t2 = perf_counter()
                packets = hiplib.process_l2_frame(frame, ihit, rhit, hip_config.config["switch"]["source_ip"]);
                t3 = perf_counter()
                perfstats.record("l2_process", t3 - t2)
                for (hip, packet, dest) in packets:
                    #logging.debug("Sending L2 frame to: %s %s" % (hexlify(ihit), hexlify(rhit)))
                    if not hip:
                        t4 = perf_counter()
                        ip_sec_socket.sendto(packet, dest)
                        t5 = perf_counter()
                        perfstats.record("ipsec_send", t5 - t4)
                        perfstats.incr_bytes("tx_bytes", len(packet))
                    else:
                        hip_socket.sendto(packet, dest)
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
    counter = 0
    while True:
        try:
            packets = hiplib.maintenance();
            for (packet, dest) in packets:
                hip_socket.sendto(packet, dest)
            logging.debug("...Periodic cleaning task...")
            counter += 1
            # Flush the data-plane perf table every 5 seconds.
            if counter % 200 == 0:
                perfstats.report()
            sleep(1);
        except Exception as e:
            logging.critical("Exception occured while processing HIP packets in maintenance loop")
            logging.critical(e);
            sleep(1)

run_switch()
