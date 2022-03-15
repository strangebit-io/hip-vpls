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

We are going to test the implementation using mininet and perhaps ONOS
in our work. But that might change of course.

# Usage

At the moment the setup is simple. We have two routers and two hosts.

First deploy the topology:

```
$ cd hip-vpls
$ sudo bash deploy.sh
```
The script should install Mininet and start the topology if it does not
run  the following command to start the topology:

```
$ sudo python3 hipls-mn.py
```

Base exchange should complete its execution in a few seconds. 

Once BEX is done, you should be able to ping h2 from h1 as follows:

```
mininet> h1 ping h2
```

You can view the progress of the BEX and other interaction in the logs:

```
$ tail -f router1/hipls.log
```

