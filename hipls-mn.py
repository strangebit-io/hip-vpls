#!/usr/bin/python

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

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()


class NetworkTopo( Topo ):

    def build( self, **_opts ):
        router1 = self.addNode( 'r1', cls=LinuxRouter )
        router2 = self.addNode( 'r2', cls=LinuxRouter )
        s1, s2 = [ self.addSwitch( s ) for s in ( 's1', 's2' ) ]
        self.addLink( router1, router2, 
                intfName1='r1-eth1', 
                intfName2='r2-eth1',
                params1={ 'ip' : '192.168.3.1/24' }, 
                params2={ 'ip' : '192.168.3.2/24' } )
        self.addLink( s1, router1, intfName2='r1-eth0',
                      params2={ 'ip' : '192.168.1.1/24' } )
        self.addLink( s2, router2, intfName2='r2-eth0',
                params2={ 'ip' : '192.168.2.1/24' } )
        h1 = self.addHost( 'h1', ip='192.168.1.100/24',
                           defaultRoute='via 192.168.1.1' )
        h2 = self.addHost( 'h2', ip='192.168.2.100/24',
                           defaultRoute='via 192.168.2.1' )
        for h, s in [ (h1, s1), (h2, s2) ]:
            self.addLink( h, s )

def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo, switch=OVSKernelSwitch)
    net.start()
    info( net[ 'r1' ].cmd( 'ifconfig r1-eth1 192.168.3.1 netmask 255.255.255.0' ) )
    info( net[ 'r2' ].cmd( 'ifconfig r2-eth1 192.168.3.2 netmask 255.255.255.0' ) )
    info( '*** Routing Table on Router:\n' )
    info( net[ 'r1' ].cmd( 'route' ) )
    info( '*** Routing Table on Router:\n' )
    info( net[ 'r2' ].cmd( 'route' ) )
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
