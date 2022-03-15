#!/usr/bin/python

"""
linuxrouter.py: Example network with Linux IP router
This example converts a Node into a router using IP forwarding
already built into Linux.
The example topology creates a router and three IP subnets:
    - 192.168.1.0/24 (r0-eth1, IP: 192.168.1.1)
    - 172.16.0.0/12 (r0-eth2, IP: 172.16.0.1)
    - 10.0.0.0/8 (r0-eth3, IP: 10.0.0.1)
Each subnet consists of a single host connected to
a single switch:
    r0-eth1 - s1-eth1 - h1-eth0 (IP: 192.168.1.100)
    r0-eth2 - s2-eth1 - h2-eth0 (IP: 172.16.0.100)
    r0-eth3 - s3-eth1 - h3-eth0 (IP: 10.0.0.100)
The example relies on default routing entries that are
automatically created for each router interface, as well
as 'defaultRoute' parameters for the host interfaces.
Additional routes may be added to the router or hosts by
executing 'ip route' or 'route' commands on the router or hosts.
"""



from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node,Controller, OVSKernelSwitch, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )
        self.cmd( 'python3 ')

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()


class NetworkTopo( Topo ):

    def build( self, **_opts ):
        router1 = self.addNode( 'r1', cls=LinuxRouter )
        router2 = self.addNode( 'r2', cls=LinuxRouter )
        s1, s2 = [ self.addSwitch( s ) for s in ( 's1', 's2' ) ]
        self.addLink( s1, router1, intfName2='r1-eth1',
                      params2={ 'ip' : '192.168.1.1/24' } )
        self.addLink( s2, router2, intfName2='r0-eth1',
                params2={ 'ip' : '192.168.2.1/24' } )
        self.addLink( router1, router2, 
                intfName1='r1-eth2', 
                intfName2='r2-eth2',
                params1={ 'ip' : '192.168.3.1/24' }, 
                params2={ 'ip' : '192.168.3.2/24' } )
        h1 = self.addHost( 'h1', ip='192.168.1.100/24',
                           defaultRoute='via 192.168.1.1' )
        h2 = self.addHost( 'h2', ip='192.168.2.100/12',
                           defaultRoute='via 192.168.2.1' )
        for h, s in [ (h1, s1), (h2, s2) ]:
            self.addLink( h, s )

def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo, switch=OVSKernelSwitch)
    net.start()
    info( '*** Routing Table on Router:\n' )
    info( net[ 'r0' ].cmd( 'route' ) )
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()