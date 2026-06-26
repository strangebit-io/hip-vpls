#!/usr/bin/python3

# Lightweight, low-overhead data-plane performance counters.
#
# Goal: find which stage of the HIP-VPLS data path limits throughput
# WITHOUT logging per packet (which would itself dominate the cost).
#
# Usage:
#   from hiplib.utils import perfstats
#   t = perfstats.now()
#   ... do work ...
#   perfstats.record("stage_name", perfstats.now() - t)
#   perfstats.incr_bytes("tx_bytes", len(packet))
#
# Periodically (e.g. once per second from the maintenance loop):
#   perfstats.report()
#
# This accumulates (count, total_time, max_time) per named stage in memory
# and flushes a compact aggregate table to a dedicated perf.log every time
# report() is called, then resets the interval counters.

import threading
from time import perf_counter

# High resolution monotonic clock; exported so callers use the same source.
now = perf_counter

# Dedicated logger -> perf.log (separate from hipls.log so it is easy to read
# and so it does not interleave with the protocol logging).
import logging
from logging.handlers import RotatingFileHandler

_perf_logger = logging.getLogger("hipls.perf")
_perf_logger.setLevel(logging.INFO)
_perf_logger.propagate = False
if not _perf_logger.handlers:
    _h = RotatingFileHandler("perf.log", maxBytes=5 * 1024 * 1024, backupCount=2)
    _h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    _perf_logger.addHandler(_h)

def reinit(filename):
    """Point the perf logger at a different file (used by a separate
    data-plane process so it does not share/rotate one file with the parent)."""
    global _perf_logger
    for h in list(_perf_logger.handlers):
        _perf_logger.removeHandler(h)
    h = RotatingFileHandler(filename, maxBytes=5 * 1024 * 1024, backupCount=2)
    h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    _perf_logger.addHandler(h)


_lock = threading.Lock()
# name -> [count, total_seconds, max_seconds]
_timers = {}
# name -> [count, total_bytes]
_counters = {}
_interval_start = perf_counter()


def record(name, dt):
    """Record one timing sample (seconds) for a named stage."""
    with _lock:
        s = _timers.get(name)
        if s is None:
            _timers[name] = [1, dt, dt]
        else:
            s[0] += 1
            s[1] += dt
            if dt > s[2]:
                s[2] = dt


def incr_bytes(name, nbytes):
    """Record a byte/packet sample (one packet of nbytes bytes)."""
    with _lock:
        c = _counters.get(name)
        if c is None:
            _counters[name] = [1, nbytes]
        else:
            c[0] += 1
            c[1] += nbytes


def report():
    """Flush the aggregate table to perf.log and reset interval counters."""
    global _interval_start, _timers, _counters
    with _lock:
        timers = _timers
        counters = _counters
        start = _interval_start
        _timers = {}
        _counters = {}
        _interval_start = perf_counter()

    interval = _interval_start - start
    if interval <= 0:
        return
    if not timers and not counters:
        return

    lines = []
    lines.append("==== perf interval %.3fs ====" % interval)
    # Stage timers: count, busy% of the interval, avg latency, max latency.
    # busy% ~ how much of the wall-clock this thread spent inside the stage.
    # If recv has high busy% the loop is starved (waiting), not CPU-bound.
    lines.append("%-16s %8s %7s %10s %10s %10s" %
                 ("stage", "count", "busy%", "total_ms", "avg_us", "max_us"))
    for name in sorted(timers.keys()):
        count, total, mx = timers[name]
        busy = 100.0 * total / interval
        avg_us = (total / count) * 1e6 if count else 0.0
        lines.append("%-16s %8d %6.1f%% %10.2f %10.1f %10.1f" %
                     (name, count, busy, total * 1e3, avg_us, mx * 1e6))
    # Byte counters -> throughput and packet rate over the interval.
    for name in sorted(counters.keys()):
        count, nbytes = counters[name]
        mbps = (nbytes * 8.0 / 1e6) / interval
        pps = count / interval
        avg_sz = (nbytes / count) if count else 0.0
        lines.append("%-16s %8d  %8.2f Mbit/s  %9.0f pps  %7.0f B/pkt" %
                     (name, count, mbps, pps, avg_sz))
    _perf_logger.info("\n".join(lines))
