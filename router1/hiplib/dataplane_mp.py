#!/usr/bin/python3

# Multiprocess data plane for HIP-VPLS.
#
# Rationale: the threaded data plane is limited by the Python GIL -- the hot
# TX loop (encrypt) and the reverse-direction RX loop (decrypt) serialize on a
# single core even on a many-core machine. This module runs the RX (decrypt)
# fast path in a SEPARATE process so encrypt and decrypt land on different
# cores.
#
# Layout:
#   * Main process : control plane (hip_loop) + TX (ether_loop) + maintenance.
#                    Owns the authoritative HIPLib. Pushes the SA table to the
#                    RX process over a Queue whenever it changes.
#   * RX process   : ESP recv -> decrypt (using the shadow SA table) -> send the
#                    inner Ethernet frame to the local host.
#
# Only the RX direction needs SA key material handed across the process
# boundary; TX stays in-process with the full HIPLib, unchanged.
#
# This path is selected by config["switch"]["dataplane_mode"] == "processes".
# With "threads" (the default) switchd.py runs the original in-process code and
# this module is never imported.

import socket
import logging
import traceback
import threading
import multiprocessing as mp
from queue import Empty
from time import sleep, perf_counter, time

from hiplib.hlib import HIPLib
from hiplib.packets import HIP
from hiplib.packets import IPSec
from hiplib.packets import IPv4
from hiplib.packets import EtherIP
from hiplib.packets import Ethernet
from hiplib.databases import SA
from hiplib.crypto.symmetric import NullCipher
from hiplib.utils.misc import Utils
from hiplib.utils import perfstats
from hiplib.config import config as hip_config
from switchfabric import FIB

ETH_P_ALL = 3


# ---------------------------------------------------------------------------
# SA shadow table: snapshot (main) <-> reconstruct (RX process)
# ---------------------------------------------------------------------------

def _build_snapshot(sa_db):
    """Serialize the SA database into plain, picklable tuples.

    sa_db is HIPLib.ip_sec_sa.db ({stable_str_key: SecurityAssociationRecord}).
    We only need the fields required to verify+decrypt an inbound ESP packet.
    """
    snap = {}
    for k, rec in list(sa_db.items()):
        try:
            snap[k] = (
                rec.aes_alg.ALG_ID,
                rec.hmac_alg.ALG_ID,
                bytes(rec.aes_key),
                bytes(rec.hmac_key),
                bytes(rec.src),
                bytes(rec.dst),
                rec.spi,
            )
        except Exception:
            # A record still being populated during the handshake; skip it,
            # it will be picked up on the next publish tick.
            continue
    return snap


def _reconstruct(snap):
    """Rebuild SecurityAssociationRecord objects from a snapshot.

    The cipher/HMAC objects are rebuilt from their algorithm IDs via the same
    factories the handshake uses, so decryption is byte-for-byte identical.
    """
    local = {}
    for k, (cid, hid, akey, hkey, src, dst, spi) in snap.items():
        rec = SA.SecurityAssociationRecord(cid, hid,
                                           bytearray(akey), bytearray(hkey),
                                           bytearray(src), bytearray(dst))
        rec.set_spi(spi)
        local[k] = rec
    return local


# ---------------------------------------------------------------------------
# RX process: ESP recv -> decrypt -> L2 send
# ---------------------------------------------------------------------------

def _decrypt(packet, local_sa):
    """Verify ICV and decrypt one inbound ESP packet into an Ethernet frame.

    Mirrors HIPLib.process_ip_sec_packet exactly, minus the state-machine
    bookkeeping (which lives in the main process). Returns the inner frame or
    None if there is no SA / the ICV check fails.
    """
    ipv4_packet   = IPv4.IPv4Packet(packet)
    data          = ipv4_packet.get_payload()
    ip_sec_packet = IPSec.IPSecPacket(data)

    src_str = Utils.ipv4_bytes_to_string(ipv4_packet.get_source_address())
    dst_str = Utils.ipv4_bytes_to_string(ipv4_packet.get_destination_address())

    # Same lookup key as process_ip_sec_packet's get_record(src_str, dst_str).
    sa_record = local_sa.get(src_str + "+" + dst_str)
    if not sa_record:
        return None

    hmac_alg   = sa_record.get_hmac_alg()
    cipher     = sa_record.get_aes_alg()
    hmac_key   = sa_record.get_hmac_key()
    cipher_key = sa_record.get_aes_key()

    buf = ip_sec_packet.get_byte_buffer()
    icv = buf[-hmac_alg.LENGTH:]

    _t = perf_counter()
    computed = hmac_alg.digest(buf[:-hmac_alg.LENGTH])
    perfstats.record("rx_hmac", perf_counter() - _t)
    if icv != computed:
        logging.critical("Invalid ICV in IPSec packet")
        return None

    padded_data = ip_sec_packet.get_payload()[:-hmac_alg.LENGTH]
    if isinstance(cipher, NullCipher):
        iv = bytearray([])
    else:
        iv = padded_data[:cipher.BLOCK_SIZE]
        padded_data = padded_data[cipher.BLOCK_SIZE:]

    _t = perf_counter()
    decrypted_data = cipher.decrypt(cipher_key, bytearray(iv), bytearray(padded_data))
    perfstats.record("rx_decrypt", perf_counter() - _t)
    # Strip the EtherIP header, then remove ESP padding.
    decrypted_data = decrypted_data[EtherIP.HEADER_LENGTH:]
    frame = IPSec.IPSecUtils.unpad(cipher.BLOCK_SIZE, decrypted_data)
    return frame


def _rx_main(config, sa_queue):
    # Separate log files so the two processes never fight over one rotating file.
    for h in list(logging.getLogger().handlers):
        logging.getLogger().removeHandler(h)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s",
                        handlers=[logging.FileHandler("hipls_rx.log")])
    perfstats.reinit("perf_rx.log")

    try:
        ip_sec_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPSec.IPSEC_PROTOCOL)
        ip_sec_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ip_sec_socket.bind((config["switch"]["source_ip"], IPSec.IPSEC_PROTOCOL))
        ip_sec_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        ether_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        ether_socket.bind((config["switch"]["l2interface"], 0))
    except Exception as e:
        logging.critical("RX process failed to open sockets: %s" % e)
        logging.critical(traceback.format_exc())
        return

    # Local SA table, updated only when the parent sends a new snapshot over the
    # queue (a Queue is safe to inherit across fork, unlike a Manager proxy).
    state = {"local_sa": {}, "recv": 0, "drop": 0}

    def refresher():
        while True:
            try:
                snap = None
                try:
                    snap = sa_queue.get(timeout=5)
                    # Drain any backlog and keep only the most recent snapshot.
                    while True:
                        try:
                            snap = sa_queue.get_nowait()
                        except Empty:
                            break
                except Empty:
                    snap = None
                if snap is not None:
                    state["local_sa"] = _reconstruct(snap)
                    logging.info("RX SA table updated: %d records" % len(state["local_sa"]))
                logging.info("RX stats: recv=%d drop=%d sa=%d" %
                             (state["recv"], state["drop"], len(state["local_sa"])))
                perfstats.report()
            except Exception as e:
                logging.critical("RX refresher error: %s" % e)

    threading.Thread(target=refresher, daemon=True).start()

    logging.info("RX data-plane process started (pid via fork)")
    while True:
        try:
            t0 = perf_counter()
            packet = bytearray(ip_sec_socket.recv(1518))
            t1 = perf_counter()
            perfstats.record("ipsec_recv", t1 - t0)
            state["recv"] += 1
            frame = _decrypt(packet, state["local_sa"])
            t2 = perf_counter()
            perfstats.record("ipsec_process", t2 - t1)
            if not frame:
                state["drop"] += 1
                continue
            ether_socket.send(frame)
            t3 = perf_counter()
            perfstats.record("eth_send", t3 - t2)
            perfstats.incr_bytes("rx_bytes", len(frame))
        except Exception as e:
            logging.critical("RX loop error: %s" % e)


# ---------------------------------------------------------------------------
# Main process: control plane + TX + maintenance
# ---------------------------------------------------------------------------

def run():
    config = hip_config.config

    # Hand SAs to the RX process over a Queue (safe to inherit across fork).
    # Spawn the RX process FIRST, while this process is still single-threaded.
    sa_queue = mp.Queue()
    rx_proc = mp.Process(target=_rx_main, args=(config, sa_queue), daemon=True)
    rx_proc.start()

    hiplib = HIPLib(config)

    hip_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, HIP.HIP_PROTOCOL)
    hip_socket.bind(("0.0.0.0", HIP.HIP_PROTOCOL))
    hip_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # TX uses this socket to SEND ESP packets. It also receives duplicate
    # inbound ESP copies (the RX process reads those); keep its recv buffer
    # small so unread copies do not waste memory.
    ip_sec_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPSec.IPSEC_PROTOCOL)
    ip_sec_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ip_sec_socket.bind((config["switch"]["source_ip"], IPSec.IPSEC_PROTOCOL))
    ip_sec_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        ip_sec_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    except Exception:
        pass

    ether_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    ether_socket.bind((config["switch"]["l2interface"], 0))
    # CRITICAL for the multiprocess split: the RX process transmits decrypted
    # frames out this same interface on its own socket. This (separate) TX
    # socket would otherwise receive copies of those outgoing frames
    # (PACKET_OUTGOING) and re-encrypt them -> infinite forwarding loop. Ask
    # the kernel to not deliver outgoing frames (Linux >= 4.20); we also filter
    # by packet type in the loop below as a portable fallback.
    try:
        PACKET_IGNORE_OUTGOING = 23
        ether_socket.setsockopt(socket.SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
    except Exception:
        pass

    fib = FIB(config["switch"]["mesh"])

    def hip_loop():
        while True:
            try:
                packet = bytearray(hip_socket.recv(1518))
                packets = hiplib.process_hip_packet(packet)
                for (packet, dest) in packets:
                    hip_socket.sendto(packet, dest)
                # An SA may have just been (re)established; publish promptly.
                _publish(hiplib, sa_queue)
            except Exception as e:
                logging.debug("Exception occured while processing HIP packet")
                logging.debug(traceback.format_exc())

    def ether_loop():
        # TX fast path: identical to switchd.py's ether_loop.
        while True:
            try:
                t0 = perf_counter()
                buf, addr = ether_socket.recvfrom(1518)
                t1 = perf_counter()
                perfstats.record("eth_recv", t1 - t0)
                # Skip frames the RX process transmitted out this interface;
                # processing them would re-encrypt our own output (loop).
                if addr[2] == socket.PACKET_OUTGOING:
                    continue
                buf = bytearray(buf)
                frame = Ethernet.EthernetFrame(buf)
                dst_mac = frame.get_destination()
                mesh = fib.get_next_hop(dst_mac)
                for (ihit, rhit) in mesh:
                    t2 = perf_counter()
                    packets = hiplib.process_l2_frame(frame, ihit, rhit, config["switch"]["source_ip"])
                    t3 = perf_counter()
                    perfstats.record("l2_process", t3 - t2)
                    for (hip, packet, dest) in packets:
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

    threading.Thread(target=hip_loop, args=(), daemon=True).start()
    threading.Thread(target=ether_loop, args=(), daemon=True).start()

    logging.info("Starting the switchd (multiprocess data plane)")

    counter = 0
    while True:
        try:
            packets = hiplib.maintenance()
            for (packet, dest) in packets:
                hip_socket.sendto(packet, dest)
            _publish(hiplib, sa_queue)
            counter += 1
            if counter % 5 == 0:
                perfstats.report()
            sleep(1)
        except Exception as e:
            logging.critical("Exception occured in maintenance loop")
            logging.critical(e)
            sleep(1)


# Cache of the last published snapshot so we only push to the RX process when
# something actually changed.
_last_snapshot = {}


def _publish(hiplib, sa_queue):
    global _last_snapshot
    snap = _build_snapshot(hiplib.ip_sec_sa.db)
    if snap == _last_snapshot:
        return
    _last_snapshot = snap
    sa_queue.put(snap)
