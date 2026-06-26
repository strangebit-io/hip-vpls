#!/usr/bin/python3
"""
Non-interactive CI smoke test for the HIP-VPLS kernel data plane.

It reuses the exact topology from hipls-mn.py (no duplication), starts switchd
on every PE, then verifies the two things that prove the kernel data plane is
working end to end:

  1. h1 can ping h2 (>= MIN_REPLIES of 30).  The first packets only succeed
     once the HIP base exchange has completed and the kernel XFRM ESP states
     are installed, so a successful ping is itself the readiness signal.
  2. `ip -s xfrm state` on r1 is non-empty (the ESP SAs were installed).

Exit code 0 = pass, 1 = fail.  Must be run as root (mininet requirement).
"""

import importlib.util
import os
import re
import sys
import time

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, OVSController
from mininet.log import setLogLevel

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

H2_IP = "192.168.1.101"          # h2's customer address
PING_COUNT = 30                  # the authoritative ping run
MIN_REPLIES = 25                 # allow a little warm-up loss, still meaningful
READY_TIMEOUT = 240              # seconds to wait for BEX + SA install
ROUTERS = (1, 2, 3, 4)


def log(msg):
    print("[ci] %s" % msg, flush=True)


def load_topology():
    """Import NetworkTopo straight from hipls-mn.py (the __main__ guard keeps
    run()/CLI from firing on import)."""
    path = os.path.join(BASE, "hipls-mn.py")
    spec = importlib.util.spec_from_file_location("hipls_mn", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.NetworkTopo


def start_daemons(net):
    """Replicate the post-start setup from hipls-mn.py:run() (minus the CLI)."""
    for i in ROUTERS:
        net["r%d" % i].cmd("ifconfig r%d-eth1 192.168.3.%d netmask 255.255.255.0" % (i, i))
        net["h%d" % i].cmd("ifconfig h%d-eth0 mtu 1400" % i)
        net["s%d" % i].cmd("ovs-vsctl set bridge s%d stp_enable=true" % i)
    for i in ROUTERS:
        rdir = os.path.join(BASE, "router%d" % i)
        net["r%d" % i].cmd("cd %s && python3 switchd.py > /tmp/switchd-r%d.log 2>&1 &" % (rdir, i))
        log("started switchd on r%d" % i)


def wait_for_connectivity(net, timeout):
    """Poll h1 -> h2 until it replies; this is the BEX-complete / SA-installed
    signal. Returns the elapsed seconds, or None on timeout."""
    h1 = net["h1"]
    start = time.time()
    while time.time() - start < timeout:
        out = h1.cmd("ping -c 1 -W 2 %s" % H2_IP)
        if " 0% packet loss" in out:
            return time.time() - start
        time.sleep(3)
    return None


def check_xfrm_state(net):
    """Return the number of installed ESP SAs visible on r1."""
    state = net["r1"].cmd("ip -s xfrm state")
    return state, len(re.findall(r"proto esp", state))


def dump_diagnostics(net):
    log("---- diagnostics (r1) ----")
    print(net["r1"].cmd("ip -s xfrm state"), flush=True)
    print(net["r1"].cmd("ip xfrm policy"), flush=True)
    print(net["r1"].cmd("bridge link"), flush=True)
    for i in ROUTERS:
        log("---- tail router%d/hipls.log ----" % i)
        print(net["r%d" % i].cmd("tail -n 25 %s" % os.path.join(BASE, "router%d/hipls.log" % i)), flush=True)


def main():
    if os.geteuid() != 0:
        log("must be run as root"); return 1

    setLogLevel("warning")
    os.system("mn -c >/dev/null 2>&1")

    NetworkTopo = load_topology()
    net = Mininet(topo=NetworkTopo(), switch=OVSKernelSwitch, controller=OVSController)
    ok = False
    try:
        net.start()
        start_daemons(net)

        log("waiting up to %ds for BEX + XFRM SA install (h1 -> h2)..." % READY_TIMEOUT)
        elapsed = wait_for_connectivity(net, READY_TIMEOUT)
        if elapsed is None:
            log("FAIL: h1 never reached h2 within %ds (control/data plane never came up)" % READY_TIMEOUT)
            dump_diagnostics(net)
            return 1
        log("connectivity up after %.1fs" % elapsed)

        # Authoritative ping run.
        out = net["h1"].cmd("ping -c %d %s" % (PING_COUNT, H2_IP))
        m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
        received = int(m.group(2)) if m else 0
        log("ping -c %d h2: %d/%d replies" % (PING_COUNT, received, PING_COUNT))
        if received < MIN_REPLIES:
            log("FAIL: only %d/%d replies (need >= %d)" % (received, PING_COUNT, MIN_REPLIES))
            dump_diagnostics(net)
            return 1

        # The ping replied, so the data plane is up -> the SAs must be present.
        state, esp_sas = check_xfrm_state(net)
        log("r1 ip -s xfrm state: %d ESP SA(s) installed" % esp_sas)
        if esp_sas < 1:
            log("FAIL: r1 xfrm state is empty despite successful ping")
            print(state, flush=True)
            dump_diagnostics(net)
            return 1

        log("PASS: %d/%d ping replies and %d ESP SA(s) installed on r1" % (received, PING_COUNT, esp_sas))
        ok = True
        return 0
    finally:
        try:
            net.stop()
        except Exception:
            pass
        os.system("mn -c >/dev/null 2>&1")
        log("done (%s)" % ("PASS" if ok else "FAIL"))


if __name__ == "__main__":
    sys.exit(main())
