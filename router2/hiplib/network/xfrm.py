"""
Kernel data-plane helpers for HIP-VPLS.

The HIP control plane (BEX) stays in Python; this module pushes the *data
plane* into the Linux kernel so that encryption, encapsulation and L2
forwarding run at line rate instead of in a Python raw-socket loop.

Design (per PE / router):

    h ── <l2interface> ──┐
                         br0  (Linux bridge == VPLS MAC learning)
                         └── gretapN  (L2-over-IP, local<->remote provider IP)
                                  │
                       kernel XFRM ESP (transport mode, AES-NI)
                                  │
                          <provider interface>

  * The bridge + gretap + XFRM *policies* are static (endpoints come from the
    config / mesh) and are installed once at start-up by setup_l2_transport().
  * The XFRM *states* (the actual keys + SPIs) are installed by install_sa()
    when a HIP association reaches ESTABLISHED, using keys derived from the
    BEX keymat.

All SPIs and per-direction keys are derived deterministically from data that
is identical on both routers (the shared keymat and the global HIT ordering),
so the two ends always agree without trusting HIP's (inconsistent) ESP_INFO
SPI bookkeeping.
"""

import logging
import subprocess
import hashlib
from binascii import hexlify

# ESP suites we can install in the kernel, keyed by their RFC 7402 ESP_TRANSFORM
# suite ID. The table is small and explicit on purpose.
#
# There are two shapes:
#   "cbc"  -- a block cipher plus a separate HMAC for authentication
#             (ip xfrm ... enc <cipher> <key> auth-trunc <hmac> <key> <bits>)
#   "aead" -- one combined algorithm that encrypts and authenticates at once
#             (ip xfrm ... aead <alg> <key+salt> <icv_bits>)
#
# Key and salt lengths are in bytes; trunc/ICV lengths are in bits.
TRANSFORMS = {
    # AES-128-CBC with HMAC-SHA-256 -- RFC 7402 suite 8 (0x08).
    0x8: {
        "kind": "cbc",
        "enc": "cbc(aes)",      "enc_key_len": 16,
        "auth": "hmac(sha256)", "auth_key_len": 32, "trunc_bits": 128,
    },
    # AES-256-CBC with HMAC-SHA-256 -- RFC 7402 suite 9 (0x09).
    0x9: {
        "kind": "cbc",
        "enc": "cbc(aes)",      "enc_key_len": 32,
        "auth": "hmac(sha256)", "auth_key_len": 32, "trunc_bits": 128,
    },
    # AES-GCM with an 8-octet ICV -- RFC 7402 suite 12 (0x0c), see RFC 4106.
    # AEAD: one AES-128 key plus a 4-byte salt, and a 64-bit (8-octet) tag.
    0xc: {
        "kind": "aead",
        "aead": "rfc4106(gcm(aes))", "enc_key_len": 16,
        "salt_len": 4, "icv_bits": 64,
    },
}


def select_transform(supported_suits):
    """
    Pick the ESP suite the kernel data plane will use: the largest suite ID in
    the configured list that we actually know how to install (see TRANSFORMS).
    Both PEs share the same config, so each one picks the same suite on its own.
    Returns the suite ID, or None if nothing in the list is supported.
    """
    usable = [s for s in supported_suits if s in TRANSFORMS]
    return max(usable) if usable else None


def _run(cmd, check=False):
    """Run an `ip` command, returning True on success. Never raises.

    Failures of commands marked check=True are logged at ERROR so they are
    visible even when the root logger is configured at ERROR level.
    """
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if res.returncode != 0 and check:
            logging.error("Command failed (%d): %s\n%s",
                res.returncode, " ".join(cmd), res.stderr.decode(errors="replace").strip())
        return res.returncode == 0
    except Exception as e:
        logging.error("Could not run %s: %s", " ".join(cmd), e)
        return False


def _link_exists(name):
    try:
        res = subprocess.run(["ip", "link", "show", "dev", name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return res.returncode == 0
    except Exception:
        return False


def _capture_ipv4(iface):
    """Return the first 'addr/prefix' currently on iface, or None."""
    try:
        res = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in res.stdout.decode(errors="replace").splitlines():
            parts = line.split()
            if "inet" in parts:
                return parts[parts.index("inet") + 1]
    except Exception as e:
        logging.warning("Could not read address of %s: %s", iface, e)
    return None


def derive_spis(keymat):
    """
    Deterministically derive the two ESP SPIs (one per direction) from the
    shared keymat. Identical on both routers because keymat is identical.
    Returns (spi_small_to_large, spi_large_to_small) as ints in [0x1000, 2^32).
    """
    h = hashlib.sha256(bytes(keymat)).digest()
    spi_s2l = int.from_bytes(h[0:4], "big")
    spi_l2s = int.from_bytes(h[4:8], "big")
    # Avoid the 0..255 range reserved by IANA / the kernel and ensure the two
    # SPIs differ.
    spi_s2l = (spi_s2l | 0x00001000) & 0xFFFFFFFF
    spi_l2s = (spi_l2s | 0x00001000) & 0xFFFFFFFF
    if spi_s2l == spi_l2s:
        spi_l2s = (spi_l2s ^ 0x00010000) & 0xFFFFFFFF
    return (spi_s2l, spi_l2s)


def install_state(src_ip, dst_ip, spi, transform_id, keys):
    """
    Install (replace) one transport-mode ESP XFRM state for traffic
    src_ip -> dst_ip with the given SPI, using the algorithm of transform_id
    (see TRANSFORMS). `keys` holds the raw key bytes for that algorithm:
      * cbc  -> {"enc": <bytes>, "auth": <bytes>}
      * aead -> {"key": <bytes>, "salt": <bytes>}
    """
    spec = TRANSFORMS[transform_id]
    spi_hex = "0x%08x" % spi

    # Build the algorithm part of the command, and a short line for the log.
    if spec["kind"] == "cbc":
        enc_hex  = "0x" + hexlify(bytes(keys["enc"])).decode("ascii")
        auth_hex = "0x" + hexlify(bytes(keys["auth"])).decode("ascii")
        algo = ["enc", spec["enc"], enc_hex,
                "auth-trunc", spec["auth"], auth_hex, str(spec["trunc_bits"])]
        descr = "enc=%s auth=%s" % (spec["enc"], spec["auth"])
    else:
        # AEAD (e.g. GCM): the kernel wants the key and salt as one blob,
        # and the ICV (tag) length in bits.
        blob = "0x" + hexlify(bytes(keys["key"]) + bytes(keys["salt"])).decode("ascii")
        algo = ["aead", spec["aead"], blob, str(spec["icv_bits"])]
        descr = "aead=%s icv=%d" % (spec["aead"], spec["icv_bits"])

    # Sanity log: exactly what is being pushed into the kernel.
    logging.getLogger("hipvpls").info(
        "xfrm state -> src=%s dst=%s spi=%s mode=transport suite=0x%x %s",
        src_ip, dst_ip, spi_hex, transform_id, descr)

    # Remove any stale state with the same selector first (re-keying / re-BEX).
    _run(["ip", "xfrm", "state", "deleteall",
          "src", src_ip, "dst", dst_ip, "proto", "esp", "spi", spi_hex])

    return _run([
        "ip", "xfrm", "state", "add",
        "src", src_ip, "dst", dst_ip,
        "proto", "esp", "spi", spi_hex,
        "mode", "transport",
        "reqid", "0",
    ] + algo + [
        "sel", "src", src_ip, "dst", dst_ip,
    ], check=True)


def _install_policy(src_ip, dst_ip, direction):
    """Install an XFRM policy requiring ESP for GRE between src_ip and dst_ip."""
    _run(["ip", "xfrm", "policy", "delete",
          "dir", direction,
          "src", src_ip + "/32", "dst", dst_ip + "/32", "proto", "gre"])
    return _run([
        "ip", "xfrm", "policy", "add",
        "dir", direction,
        "src", src_ip + "/32", "dst", dst_ip + "/32", "proto", "gre",
        "tmpl", "src", src_ip, "dst", dst_ip, "proto", "esp", "mode", "transport",
    ], check=True)


def setup_policies(local_ip, remote_ip):
    """Install the (static) XFRM policies for the GRE tunnel both directions."""
    # Locally-originated GRE towards the peer must be ESP-protected (out), and
    # received GRE must have arrived via ESP (in).
    _install_policy(local_ip, remote_ip, "out")
    _install_policy(remote_ip, local_ip, "in")


def pseudowire_name(prefix, remote_ip):
    """
    Stable, unique, <=15-char device name for the pseudowire to a given remote
    provider IP. Derived from the last octet of the provider IP (the provider
    network is a small shared subnet, so last octets are unique). Computed the
    same way in setup and teardown.

    NOTE: do not let the result be "gretap0"/"gre0" -- those are auto-created
    fallback devices owned by the ip_gre module, and `ip link add gretap0 ...`
    collides with them (RTNETLINK: File exists). The prefix avoids this.
    """
    return prefix + remote_ip.strip().split(".")[-1]


def _add_pseudowire(l2_bridge, gretap, local_ip, remote_ip, gretap_mtu):
    """
    Create one isolated gretap pseudowire to remote_ip and enslave it to the
    bridge. "isolated on" gives VPLS split-horizon: frames received on one
    pseudowire are never forwarded out another pseudowire (only to the
    non-isolated customer port), which keeps a full mesh loop-free without STP.
    Returns True on success.
    """
    _run(["ip", "link", "del", gretap])  # clean any stale device
    _run(["ip", "link", "add", gretap, "type", "gretap",
          "local", local_ip, "remote", remote_ip], check=True)
    if not _link_exists(gretap):
        logging.error("gretap device %s (to %s) was NOT created -- the kernel "
            "data plane will not forward to that peer.", gretap, remote_ip)
        return False
    _run(["ip", "link", "set", gretap, "mtu", str(gretap_mtu)])
    _run(["ip", "link", "set", gretap, "master", l2_bridge], check=True)
    # Split-horizon: pseudowire ports may talk to the customer port but not to
    # each other (must be run after the device is a bridge slave).
    _run(["bridge", "link", "set", "dev", gretap, "isolated", "on"], check=True)
    _run(["ip", "link", "set", gretap, "up"], check=True)

    res = subprocess.run(["ip", "-o", "link", "show", "dev", gretap],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ("master " + l2_bridge) not in res.stdout.decode(errors="replace"):
        logging.error("Pseudowire %s is NOT enslaved to %s -- forwarding to "
            "%s will be broken.", gretap, l2_bridge, remote_ip)
        return False
    logging.info("Pseudowire %s -> %s enslaved to %s (isolated/split-horizon)",
        gretap, remote_ip, l2_bridge)
    setup_policies(local_ip, remote_ip)
    return True


def setup_l2_transport(l2interface, bridge, local_ip, peer_ips,
                       prefix="hvpls", gretap_mtu=1462):
    """
    Build the static full-mesh L2 data path once at start-up:
      * create the bridge (the VPLS forwarding instance / VSI),
      * enslave the customer L2 interface (NON-isolated attachment circuit),
      * for EACH remote peer create an isolated gretap pseudowire + XFRM policy,
      * move the L2 interface's IPv4 address (if any) onto the bridge.

    peer_ips: list of remote provider IP strings (one per remote PE). This is
    derived by the caller from the mesh + hosts config files, so adding a
    router only requires editing those files -- the data plane scales itself.

    Idempotent: tears down any pre-existing bridge/pseudowires first.
    """
    logging.info("Setting up kernel L2 transport on %s, bridge %s, %d peer(s): %s",
        l2interface, bridge, len(peer_ips), ", ".join(peer_ips))

    # Preserve the customer-facing IP across restarts: on a re-run it may
    # already have been moved from the L2 interface onto the bridge.
    saved_addr = _capture_ipv4(l2interface) or _capture_ipv4(bridge)

    # Tear down anything left over from a previous run.
    for remote_ip in peer_ips:
        _run(["ip", "link", "del", pseudowire_name(prefix, remote_ip)])
    _run(["ip", "link", "del", bridge])

    # Bridge = the VPLS forwarding instance (native MAC learning + flooding).
    _run(["ip", "link", "add", bridge, "type", "bridge"], check=True)

    # The customer-facing port is the attachment circuit: pure L2, NOT isolated
    # (it must be able to reach every pseudowire), and its IP moves to the bridge.
    _run(["ip", "addr", "flush", "dev", l2interface])
    _run(["ip", "link", "set", l2interface, "master", bridge], check=True)

    # One isolated pseudowire per remote PE -> full mesh with split-horizon.
    for remote_ip in peer_ips:
        gretap = pseudowire_name(prefix, remote_ip)
        _add_pseudowire(bridge, gretap, local_ip, remote_ip, gretap_mtu)

    # Keep the router reachable / keep acting as the customer gateway.
    if saved_addr:
        _run(["ip", "addr", "add", saved_addr, "dev", bridge])

    _run(["ip", "link", "set", l2interface, "up"], check=True)
    _run(["ip", "link", "set", bridge, "up"], check=True)

    res = subprocess.run(["ip", "-o", "link", "show", "dev", l2interface],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ("master " + bridge) not in res.stdout.decode(errors="replace"):
        logging.error("Customer port %s is NOT enslaved to %s -- forwarding "
            "will be broken.", l2interface, bridge)
    else:
        logging.info("Customer port %s enslaved to %s", l2interface, bridge)


def teardown(bridge, peer_ips, prefix="hvpls", local_ip=None):
    """Best-effort cleanup of the full-mesh kernel data plane."""
    for remote_ip in peer_ips:
        if local_ip:
            _run(["ip", "xfrm", "policy", "delete", "dir", "out",
                  "src", local_ip + "/32", "dst", remote_ip + "/32", "proto", "gre"])
            _run(["ip", "xfrm", "policy", "delete", "dir", "in",
                  "src", remote_ip + "/32", "dst", local_ip + "/32", "proto", "gre"])
        _run(["ip", "link", "del", pseudowire_name(prefix, remote_ip)])
    _run(["ip", "link", "del", bridge])
