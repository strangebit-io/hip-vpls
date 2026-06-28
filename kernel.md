# HIP-VPLS Kernel Data Plane

This document explains the **kernel data-plane** mode added to HIP-VPLS: what it
does, why each piece exists, how packets flow, and exactly what changed when we
moved the data plane out of Python and into the Linux kernel.

It is written to be read top-to-bottom. Every claim points at the code that
implements it.

---

## 1. Background: the problem we solved

HIP-VPLS builds a **Layer-2 VPN (VPLS)** between two PE routers (`r1`, `r2`).
Customer hosts `h1` (behind `r1`) and `h2` (behind `r2`) sit in the same subnet
`192.168.1.0/24` and must behave as if they are on **one Ethernet LAN**, even
though an IP-routed provider core (`192.168.3.0/29`) separates the two PEs. The
link is secured with keys negotiated by the **HIP base exchange (BEX)**.

### The original (Python) data plane

In the original design ([switchd.py](router1/switchd.py), `threads`/`processes`
modes) **every customer packet was handled in Python**:

1. A raw `AF_PACKET` socket read each Ethernet frame off `r1-eth0`.
2. `hlib.process_l2_frame()` wrapped it in EtherIP, **encrypted + HMAC'd it in
   Python** (ESP-like), and sent it on a raw IP socket (proto 50).
3. On the far side a raw socket read the ESP packet,
   `hlib.process_ip_sec_packet()` **decrypted it in Python**, and re-injected the
   frame onto the peer's `r2-eth0`.

Python crypto + the per-packet userspace copy capped throughput at **~170 Mbit/s**
on an otherwise gigabit network. That ceiling is the reason for this work.

### The fix

Keep the **HIP control plane in Python** (it is not performance-critical), but
move the **data plane into the Linux kernel**:

* customer L2 frames are switched by a **Linux bridge** (native MAC learning),
* carried to the remote PE by a **gretap** (L2-over-GRE) tunnel,
* and protected by **kernel XFRM ESP** using the keys HIP derived.

This is selected by a single config switch, `dataplane_mode: "kernel"`
([config.py:11](router1/hiplib/config/config.py#L11)). The old `threads` and
`processes` modes are untouched and remain available as a fallback.

---

## 2. The interfaces on each PE

Using `r1` as the example (r2 is identical with mirrored addresses):

| Interface | Type | Address | Role |
|-----------|------|---------|------|
| `r1-eth0` | physical (veth) | none (moved to `br0`) | **Customer / attachment circuit.** Faces `h1` via switch `s1`. Carries raw customer Ethernet frames. |
| `r1-eth1` | physical (veth) | `192.168.3.1/29` | **Provider / core.** Faces `r2` via switch `s5`. The encrypted ESP packets travel here. |
| `hvpls<N>` | `gretap` tunnel | (unnumbered) | **Pseudowire (one per remote PE).** L2-over-GRE, `local 192.168.3.1 remote <peer-IP>`. `<N>` = last octet of the peer's provider IP (e.g. `hvpls2` → r2, `hvpls3` → r3). Tunnels customer Ethernet frames to that PE. All pseudowire ports are **isolated** (split-horizon). |
| `br0`     | Linux bridge | `192.168.1.1/24` (moved off `r1-eth0`) | **VPLS forwarding instance.** Members: `r1-eth0` + one `hvpls<N>` per remote PE. |

These are created at start-up by
[`xfrm.setup_l2_transport()`](router1/hiplib/network/xfrm.py#L222).

### 2.1 Why a bridge (`br0`)?

VPLS = emulate one Ethernet segment. The PE must do what an Ethernet switch
does: **learn** which MAC is reachable through which port, **forward** known
unicast to the correct port, and **flood** broadcast / multicast / unknown
unicast to all ports. A Linux bridge does exactly this in the kernel. h1 ARPing
for h2 is a broadcast that the bridge floods out every port (including the
tunnels). This natively replaces the old Python FIB (see §5).

### 2.2 Why gretap tunnels (`hvpls<N>`), one per peer?

A bridge cannot, by itself, reach another machine across an IP core. `gretap`
is the "wire": it encapsulates each **full customer Ethernet frame** into
`GRE + outer IPv4` whose source/destination are the two **provider** IPs (e.g.
`192.168.3.1` ↔ `192.168.3.2`). The frame therefore re-emerges on the remote
PE's bridge. `gretap` (as opposed to plain `gre`) is an **Ethernet** device, so
it can be a bridge port.

In a full mesh each PE creates **one gretap per remote peer** and bridges all of
them. The set of peers is derived from the `mesh` + `hosts` config files, so
the data plane scales itself — see §5.3.

> **Naming gotcha:** the device must **not** be called `gretap0` or `gre0`.
> Loading the kernel `ip_gre` module auto-creates fallback devices with those
> exact names, so `ip link add gretap0 type gretap …` fails with *File exists*.
> We derive each name as `gretap_prefix` + last octet of the peer's provider IP
> (default prefix `hvpls`, e.g. `hvpls2`), in
> [`xfrm.pseudowire_name()`](router1/hiplib/network/xfrm.py#L174).

> **Split-horizon (loop prevention):** every pseudowire port is set
> `isolated on` ([xfrm.py `_add_pseudowire`](router1/hiplib/network/xfrm.py)),
> so a frame received on one pseudowire is **never** forwarded out another
> pseudowire — only to the (non-isolated) customer port. This is the VPLS
> split-horizon rule (RFC 4762 §4.4) and is what keeps a 3+ PE full mesh
> loop-free **without STP**. With only one pseudowire (2 PEs) it is a harmless
> no-op. See §5.3.

### 2.3 Why XFRM ESP in *transport* mode?

HIP requires the pseudowire to be authenticated and encrypted with HIP-derived
keys. We use the kernel's IPsec (XFRM) ESP for that. Because **gretap already
provides the encapsulation**, ESP only has to *protect* the GRE packets — so we
use **transport mode** (protect the payload of the existing IP packet) rather
than **tunnel mode** (which would add a second outer IP header). Transport mode
is lower overhead.

The policies say "*GRE between the two provider IPs must be ESP-protected*"
([xfrm.py:166](router1/hiplib/network/xfrm.py#L166)); the states hold the actual
keys/SPIs ([xfrm.py:121](router1/hiplib/network/xfrm.py#L121)).

---

## 3. The packet walk (h1 → h2)

```
 h1
  │  raw customer Ethernet frame (dst = h2's MAC, or broadcast for ARP)
  ▼
 r1-eth0                         ← bridge port (attachment circuit)
  │
  ▼
 br0                             ← Linux bridge: learn src MAC, decide egress port
  │   (known unicast → hvpls2 ; broadcast/unknown → flood all ports)
  ▼
 hvpls2 (gretap → r2)            ← encapsulate: [ GRE | inner Ethernet frame ]
  │                                 then add outer IPv4 192.168.3.1 → 192.168.3.2
  ▼
 IP output path
  │   XFRM policy "dir out, proto gre, .1→.2"  matches  (xfrm.py:153)
  ▼
 XFRM ESP encrypt                ← AES-128-CBC + HMAC-SHA-256, HIP keys, AES-NI
  │   ESP transport mode, SPI = out_spi
  ▼
 r1-eth1  ──── provider core (s5) ────▶  r2-eth1
                                              │  proto 50 (ESP)
                                              ▼
                                        XFRM ESP decrypt  (matched by dst+proto+SPI)
                                              │
                                              ▼
                                        GRE decapsulation
                                              │
                                              ▼
                                        hvpls1 (gretap → r1) on r2
                                              │
                                              ▼
                                        br0 on r2  ← learn h1's MAC ⇒ reachable via hvpls1
                                              │
                                              ▼
                                        r2-eth0 ──▶ h2
```

**Everything below `r1-eth0` runs in the kernel.** No Python is on the per-packet
path, and segmentation offloads (GSO/TSO/GRO) are left **on**
([hipls-mn.py](hipls-mn.py)) so the kernel can move large segments through
gretap + ESP at line rate. (The Python modes had to disable offloads so the raw
socket saw individual frames; the kernel mode wants them on.)

---

## 4. The control plane (still Python)

The HIP base exchange is unchanged and still runs in Python over a raw socket
(IP proto 139). What changed is what happens **when an association reaches
ESTABLISHED**: instead of building Python SA records for a Python ESP loop, we
install the keys into the kernel.

### 4.1 Triggering the exchange — `initiate_bex()`

In the Python modes, BEX was kicked off lazily by the first data frame arriving
at `process_l2_frame()`. In kernel mode there is no Python data loop, so nothing
would ever start BEX. We added
[`HIPLib.initiate_bex()`](router1/hiplib/hlib.py#L253), which the switch calls
once per second for each configured mesh peer
([switchd.py:189](router1/switchd.py#L189)).

To avoid a simultaneous-BEX race (both PEs initiating at once), **only the
numerically smaller HIT initiates**; the larger-HIT PE simply responds
([hlib.py](router1/hiplib/hlib.py#L259)). `process_hip_packet()` and
`maintenance()` drive the in-flight handshake and its retransmits exactly as
before.

### 4.2 Installing the kernel SAs — `install_kernel_dataplane_sa()`

When the exchange completes, the responder path
([hlib.py:1871](router1/hiplib/hlib.py#L1871)) and the initiator path
([hlib.py:2137](router1/hiplib/hlib.py#L2137)) both call
[`install_kernel_dataplane_sa()`](router1/hiplib/hlib.py#L171). It:

1. Picks the ESP transform (`0x8` ⇒ AES-128-CBC + HMAC-SHA-256) via
   `ESPTransformFactory`.
2. Derives the **per-direction keys** from the shared `keymat` using the
   existing `Utils.get_keys_esp()`, keyed by the global HIT ordering
   (smaller→larger and larger→smaller).
3. Derives the two **SPIs deterministically** from the keymat
   (`xfrm.derive_spis()`, [xfrm.py:103](router1/hiplib/network/xfrm.py#L103)).
4. Decides which direction is "out" for *this* PE (am I the smaller or larger
   HIT?) and calls `xfrm.install_state()` twice — one OUT state
   (`local→remote`) and one IN state (`remote→local`).

> **Why derive SPIs/keys deterministically instead of using HIP's ESP_INFO
> SPIs?** The original Python receive path looked SAs up by **source/destination
> IP only and never checked the SPI**, so the two PEs ended up assigning SPIs
> that did **not** match across directions. The kernel, however, matches an
> inbound SA by `(destination, protocol, SPI)`, so the SPIs *must* agree. Since
> both PEs compute an **identical `keymat`** and share the **same global HIT
> ordering**, deriving `(SPI, key)` purely from those two inputs guarantees that
> `r1`'s OUT state exactly equals `r2`'s IN state, and vice versa — without
> trusting the (inconsistent) ESP_INFO bookkeeping.

The result is fully visible in `hipls.log` (see §6) and can be cross-checked
against `ip -s xfrm state`.

### 4.3 Keeping the tunnel alive — `refresh_kernel_timers()`

The Python data plane used to refresh an association's "data timeout" every time
it saw a packet; an idle association would `CLOSE` (and the code also rekeys via
UPDATE). In kernel mode Python never sees data packets, so an established
association would idle-close and tear down its kernel SAs. To prevent that,
[`refresh_kernel_timers()`](router1/hiplib/hlib.py#L341) is called every second
([switchd.py:193](router1/switchd.py#L193)) to push the data/update timers
forward, pinning established associations (no idle-close, no rekey-driven key
desync).

---

## 5. How the FIB works now

There are effectively **two** FIBs, and the kernel transition split them:

### 5.1 Control-plane FIB — the Python `switchfabric.FIB`

[`switchfabric.FIB`](router1/switchfabric.py) is now used for **one thing at
start-up**: `load_mesh()` reads the `mesh` config file into `fib_broadcast`, a
list of `(ihit, rhit)` tunnel pairs ([switchfabric.py:31](router1/switchfabric.py#L31)).
The switch uses that list to know:

* **which peers to run BEX with** — fed to `initiate_bex()`, and
* **which provider IPs to build the gretap/SAs to** — each peer HIT is resolved
  to its provider IP via the hosts file
  ([switchd.py:128-150](router1/switchd.py#L128)).

Its **per-packet** methods are **no longer on the data path** in kernel mode:

* `get_next_hop(dst_mac)` — pick a HIP tunnel for a destination MAC — is not
  called.
* `set_next_hop(mac, ihit, rhit)` — MAC learning — is not called.

(They remain intact and are still used by the `threads`/`processes` Python
modes.)

### 5.2 Data-plane FIB — the Linux bridge FDB

The real per-frame forwarding decision now lives in the **kernel bridge's
forwarding database (FDB)**. As frames arrive on `r1-eth0` and the `hvpls<N>`
pseudowires, the bridge:

* **learns** the source MAC → ingress port,
* **forwards** known-unicast to the learned port,
* **floods** broadcast / multicast / unknown-unicast to all other ports,
* **ages** entries out automatically.

Inspect it live with:

```
bridge fdb show br br0      # learned MAC -> port table
bridge link                 # bridge ports (must show r1-eth0 AND each hvpls<N>)
```

This is exactly the VPLS MAC-learning behaviour the Python FIB used to emulate —
now done in the kernel at line rate. In short: the *concept* of "which tunnel
does this MAC go to" is unchanged; the *implementation* moved from
`switchfabric.FIB` into the kernel bridge, and the Python FIB degenerated into a
start-up "list of tunnels to establish."

### 5.3 Scaling to N PEs (adding a router)

Nothing in the data-plane setup is hardcoded to a peer count. At start-up
[`switchd.py`](router1/switchd.py) reads the **`mesh`** file (peer HITs) and the
**`hosts`** file (HIT → provider IP) and builds the list of remote provider IPs,
then hands it to [`xfrm.setup_l2_transport()`](router1/hiplib/network/xfrm.py#L222),
which loops over the list and, for each peer, creates **one isolated gretap
pseudowire + one XFRM policy pair**. The per-peer XFRM **states** are installed
as each HIP association completes (§4.2). So to add `r3`:

1. **Copy** a router folder (e.g. `router1/` → `router3/`).
2. Edit `router3/hiplib/config/config.py`: set `source_ip` (e.g. `192.168.3.3`)
   and `l2interface` (e.g. `r3-eth0`).
3. Generate `r3`'s key/HIT and add it to **every** node's `hosts` file
   (`<r3-HIT> 192.168.3.3`).
4. Add the new tunnels to **every** node's `mesh` file (full mesh: `r1↔r3`,
   `r2↔r3`, and `r3↔r1`, `r3↔r2` in r3's own mesh).
5. Add `r3` and its links/MTU to [`hipls-mn.py`](hipls-mn.py).

On the next start, each PE automatically runs BEX with all peers and builds one
isolated pseudowire per peer. r1 would then have `br0` = { `r1-eth0`, `hvpls2`,
`hvpls3` }. The `isolated on` flag (§2.2) provides VPLS split-horizon, so the
full mesh is loop-free without STP.

**Worked example — h1 pings h3 (cold caches), focusing on r1's FDB:**

* h1's **ARP request** (broadcast) ingresses `r1-eth0`; r1 learns
  `h1-MAC → r1-eth0` and **floods** it out `hvpls2` *and* `hvpls3`.
* r3 receives it on its pseudowire-from-r1, learns `h1-MAC → that PW`, floods to
  its customer port → **h3 sees the ARP**. (r2 also receives the flood and
  learns h1, but split-horizon stops it relaying to r3, so there is no
  duplicate/loop.)
* h3's **ARP reply** (unicast) comes back over the pseudowire; r1 receives it on
  `hvpls3` and **learns `h3-MAC → hvpls3`**.
* The **ICMP echo** is now unicast: r1 looks up `h3-MAC → hvpls3` and forwards
  out only that one pseudowire.

**Second ping:** all FDBs (and ARP caches) are still warm, so it is pure unicast
`r1 → hvpls3 → r3`, no flooding, r2 untouched. This matches VPLS flood-and-learn
semantics exactly.

---

## 6. Logging / observability

A dedicated logger named `hipvpls`, set to `INFO`, is used for the sanity
output. Because the per-logger level check passes `INFO` and the record still
propagates to the shared `hipls.log` file handler, these lines appear **even
though the root logger is at `ERROR`** — without unleashing the rest of the
codebase's debug output.

What gets logged:

* **BEX → XFRM parameters** ([hlib.py](router1/hiplib/hlib.py#L171), in
  `install_kernel_dataplane_sa`): local/remote provider IP, own/initiator/
  responder HITs, this PE's role, ESP transform, keymat index, and for each
  direction the SPI + enc key + auth key.
* **What the xfrm module installs** ([xfrm.py:121](router1/hiplib/network/xfrm.py#L121)):
  one `xfrm state -> src=… dst=… spi=… enc=… auth=…` line per SA.
* **FIB / next-hop data** ([switchfabric.py:43](router1/switchfabric.py#L43)):
  each mesh tunnel loaded; newly learned MAC→tunnel bindings (Python modes); and
  in kernel mode, the resolved tunnel endpoints (peer HIT → provider IP) plus the
  local interface/bridge/gretap names ([switchd.py](router1/switchd.py)).

Filter it with, e.g.:

```
grep -E "BEX -> kernel|xfrm state ->|FIB|next-hop" router1/hipls.log
```

---

## 7. Summary of changes (Python data plane → kernel data plane)

| Area | Before (Python data plane) | After (kernel data plane) |
|------|----------------------------|----------------------------|
| Per-packet forwarding | Raw `AF_PACKET` socket + `process_l2_frame` / `process_ip_sec_packet` | Linux **bridge** `br0` |
| Encapsulation | EtherIP inside a hand-built ESP packet | **gretap** (L2-over-GRE), one `hvpls<N>` per peer |
| Encryption / auth | Python AES + HMAC, per packet | **Kernel XFRM ESP** (AES-NI), transport mode |
| MAC learning / FIB | `switchfabric.FIB` (`get/set_next_hop`) | Kernel **bridge FDB** |
| Multi-PE / loops | Python FIB flooded to all mesh tunnels | Full mesh of isolated pseudowires (**split-horizon**), auto-built from `mesh`+`hosts` |
| BEX trigger | First data frame in `process_l2_frame` | `initiate_bex()` per peer ([hlib.py:253](router1/hiplib/hlib.py#L253)) |
| SA install | Python `SecurityAssociationRecord`s | `install_kernel_dataplane_sa()` → `ip xfrm state` ([hlib.py:171](router1/hiplib/hlib.py#L171)) |
| SPI / key agreement | ESP_INFO SPIs (inconsistent; receive ignored SPI) | **Deterministic** from keymat + HIT order ([xfrm.py:103](router1/hiplib/network/xfrm.py#L103)) |
| Idle handling | data timeout refreshed on each packet | `refresh_kernel_timers()` pins associations ([hlib.py:341](router1/hiplib/hlib.py#L341)) |
| Offloads (mininet) | GSO/TSO/GRO **off** (raw socket needs whole frames) | GSO/TSO/GRO **on** (line rate) ([hipls-mn.py](hipls-mn.py)) |
| Throughput | ~170 Mbit/s | ~line rate |

### Files touched

* **New:** [router{1,2}/hiplib/network/xfrm.py](router1/hiplib/network/xfrm.py) —
  per-peer isolated gretap pseudowire + bridge setup, XFRM policy + state install,
  deterministic SPI derivation, `pseudowire_name()`, teardown.
* [router{1,2}/hiplib/hlib.py](router1/hiplib/hlib.py) — `install_kernel_dataplane_sa()`,
  `initiate_bex()`, `refresh_kernel_timers()`, and the two install hooks at BEX
  completion.
* [router{1,2}/switchd.py](router1/switchd.py) — the `kernel` mode branch: builds
  the peer list from `mesh`+`hosts` and the maintenance/BEX/keepalive loop; no
  Python L2/ESP loops.
* [router{1,2}/hiplib/config/config.py](router1/hiplib/config/config.py) —
  `dataplane_mode: "kernel"`, `bridge`, `gretap_prefix`.
* [router{1,2}/switchfabric.py](router1/switchfabric.py) — FIB sanity logging.
* [hipls-mn.py](hipls-mn.py) — leave segmentation offloads on for kernel mode.

> Both PEs **must** run the same `dataplane_mode`: the kernel ESP/GRE format does
> not interoperate with the old Python EtherIP-in-ESP format.

### Quick verification

```
# on r1, after BEX completes:
r1 bridge link            # must show r1-eth0@br0 AND one hvpls<N>@br0 per peer
                          # (the hvpls<N> ports should be flagged "isolated on")
r1 ip -d link show hvpls2 # gretap, local .1 remote .2, state UP
r1 ip -s xfrm state       # two ESP SAs; byte/packet counters climb under load
r1 ip xfrm policy         # out/in GRE policies
h1 ping h2                # works
# throughput:
h2 iperf3 -s  ;  h1 iperf3 -c 192.168.1.101
```
