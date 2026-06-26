# About

Virtual Private LAN Services are common place in modern networking. 
This repository contains implementation of VPLS based on Host Identity Protocol.

# Introduction

Host Identity Protocol, or HIP, is layer 3.5 solution,
which was initially designed to split the dual role of the IP address: 
locator and identifier. Using HIP protocol one can solve not
only mobility problems, but also establish authenticated secure
channel. This repository contains simple implementation of HIP-VPLS.

At the moment the development is ongoing. Linux was selected as a target system and all the 
development currently done for this operating system.

We are going to test the implementation using Mininet simulation environment.

# Usage

At the moment the setup is simple. We have four routers, which form the HIP VPLS and five switches
connecting hosts and routers. There are also four hosts that are agnostic about the topology used.

First clone the repository:
```
$ cd ~
$ git clone https://github.com/strangebit-io/hip-vpls.git
```

After this step is done you can deploy the topology:

```
$ cd hip-vpls
$ sudo bash deploy.sh
```
The script should install Mininet and start the topology if it does not
run  the following command to start the topology:

```
$ cd ~
$ cd hip-vpls
$ sudo python3 hipls-mn.py
```

Base exchange should complete its execution in a few seconds. 

Once BEX is done, you should be able to ping h2 from h1 as follows (from the mininet):

```
mininet> h1 ping h2
```

You can view the progress of the BEX and other interaction in the logs:

```
$ tail -f router1/hipls.log
```

Other useful commands:

View ports' statuses
```
mininet> s4 ovs-ofctl show "s4"
```

Capture the packets between HIP switches:

```
minenet > r2 tcpdump -n -i r2-eth1 -w ipsec.pcap
```

# Kernel data plane

The original data plane handled every customer packet in Python (raw socket +
Python AES/HMAC), which capped throughput at ~170 Mbit/s. This branch adds a
kernel data plane that keeps the HIP control plane (BEX) in Python but moves
forwarding into the kernel: customer L2 frames are switched by a Linux bridge,
carried to the remote PE over a `gretap` (L2-over-GRE) tunnel, and protected by
kernel XFRM ESP using the keys HIP derived. The result is near line rate. See
[kernel.md](kernel.md) for the full design.

It is selected per router by a single switch in `hiplib/config/config.py`:

```
"dataplane_mode": "kernel"
```

The old `threads` / `processes` Python modes are untouched and remain as a
fallback. Both routers must run the same mode.

Test it after starting the topology:

```
mininet> h1 ping -c 30 h2
```

The first replies are delayed: nothing forwards until the HIP base exchange
completes and the XFRM states are installed. Once you see ping replies, the
control plane has finished and the kernel ESP data plane is up. Confirm the
installed SAs on r1 (byte/packet counters climb under load):

```
mininet> r1 ip -s xfrm state
```

