#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSController, OVSKernelSwitch
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
        hub1 = self.addNode( 'hu1', cls=LinuxRouter )
        hub2 = self.addNode( 'hu2', cls=LinuxRouter )
        hub3 = self.addNode( 'hu3', cls=LinuxRouter )

        spoke1 = self.addNode( 'sp1', cls=LinuxRouter )
        spoke2 = self.addNode( 'sp2', cls=LinuxRouter )
        spoke3 = self.addNode( 'sp3', cls=LinuxRouter )

        switch1 = self.addSwitch( 'sw1', cls=OVSKernelSwitch)
        switch2 = self.addSwitch( 'sw2', cls=OVSKernelSwitch)
        switch3 = self.addSwitch( 'sw3', cls=OVSKernelSwitch)
        switch4 = self.addSwitch( 'sw4', cls=OVSKernelSwitch)


        

        self.addLink(spoke1, switch2)
        self.addLink(spoke2, switch3)
        self.addLink(spoke3, switch4)

        self.addLink(hub1, switch2)
        self.addLink(hub2, switch3)
        self.addLink(hub3, switch4)

        self.addLink(hub1, switch1)
        self.addLink(hub2, switch1)
        self.addLink(hub3, switch1)

        # router1 = self.addNode( 'r1', cls=LinuxRouter )
        # router2 = self.addNode( 'r2', cls=LinuxRouter )
        # router3 = self.addNode( 'r3', cls=LinuxRouter )
        # router4 = self.addNode( 'r4', cls=LinuxRouter )
        # s1, s2, s3, s4, s5 = [ self.addSwitch( s, cls=OVSKernelSwitch ) for s in ( 's1', 's2', 's3', 's4', 's5' ) ]
        # self.addLink( s5, router1,
        #         intfName2='r1-eth1',
        #         params2={ 'ip' : '192.168.3.1/29' } )
        # self.addLink( s5, router2,
        #         intfName2='r2-eth1',
        #         params2={ 'ip' : '192.168.3.2/29' } )
        # self.addLink( s5, router3,
        #         intfName2='r3-eth1',
        #         params2={ 'ip' : '192.168.3.3/29' } )
        # self.addLink( s5, router4,
        #         intfName2='r4-eth1',
        #         params2={ 'ip' : '192.168.3.3/29' } )
        # self.addLink( s1, router1, intfName2='r1-eth0',
        #               params2={ 'ip' : '192.168.1.1/24' } )
        # self.addLink( s2, router2, intfName2='r2-eth0',
        #         params2={ 'ip' : '192.168.1.2/24' } )
        # self.addLink( s3, router3, intfName2='r3-eth0',
        #         params2={ 'ip' : '192.168.1.3/24' } )
        # self.addLink( s4, router4, intfName2='r4-eth0',
        #         params2={ 'ip' : '192.168.1.4/24' } )
        # h1 = self.addHost( 'h1', ip='192.168.1.100/24',
        #                    defaultRoute='via 192.168.1.1' )
        # h2 = self.addHost( 'h2', ip='192.168.1.101/24',
        #                    defaultRoute='via 192.168.1.1' )
        # h3 = self.addHost( 'h3', ip='192.168.1.102/24',
        #                    defaultRoute='via 192.168.1.1' )
        # h4 = self.addHost( 'h4', ip='192.168.1.103/24',
        #                    defaultRoute='via 192.168.1.1' )
        # for h, s in [ (h1, s1), (h2, s2), (h3, s3), (h4, s4) ]:
        #     self.addLink( h, s )
from time import sleep
def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo, switch=OVSKernelSwitch, controller = OVSController)
    net.start()
    # info( net[ 'r1' ].cmd( 'ifconfig r1-eth1 192.168.3.1 netmask 255.255.255.248' ) )
    # info( net[ 'r2' ].cmd( 'ifconfig r2-eth1 192.168.3.2 netmask 255.255.255.248' ) )
    # info( net[ 'r3' ].cmd( 'ifconfig r3-eth1 192.168.3.3 netmask 255.255.255.248' ) )
    # info( net[ 'r4' ].cmd( 'ifconfig r4-eth1 192.168.3.4 netmask 255.255.255.248' ) )

    # info( net[ 'r1' ].cmd( '/sbin/ethtool -K r1-eth0 rx off tx off sg off' ) )
    # info( net[ 'r1' ].cmd( '/sbin/ethtool -K r1-eth1 rx off tx off sg off' ) )
    # info( net[ 'r2' ].cmd( '/sbin/ethtool -K r2-eth0 rx off tx off sg off' ) )
    # info( net[ 'r2' ].cmd( '/sbin/ethtool -K r2-eth1 rx off tx off sg off' ) )
    # info( net[ 'r3' ].cmd( '/sbin/ethtool -K r3-eth0 rx off tx off sg off' ) )
    # info( net[ 'r4' ].cmd( '/sbin/ethtool -K r3-eth1 rx off tx off sg off' ) )
    # info( net[ 'r4' ].cmd( '/sbin/ethtool -K r4-eth0 rx off tx off sg off' ) )
    # info( net[ 'r4' ].cmd( '/sbin/ethtool -K r4-eth1 rx off tx off sg off' ) )

    # info( net[ 'h1' ].cmd( '/sbin/ethtool -K h1-eth0 rx off tx off sg off' ) )
    # info( net[ 'h2' ].cmd( '/sbin/ethtool -K h2-eth0 rx off tx off sg off' ) )
    # info( net[ 'h3' ].cmd( '/sbin/ethtool -K h3-eth0 rx off tx off sg off' ) )
    # info( net[ 'h4' ].cmd( '/sbin/ethtool -K h4-eth0 rx off tx off sg off' ) )


    # info( net[ 'h1' ].cmd( 'ifconfig h1-eth0 mtu 1400' ) )
    # info( net[ 'h2' ].cmd( 'ifconfig h2-eth0 mtu 1400' ) )
    # info( net[ 'h3' ].cmd( 'ifconfig h3-eth0 mtu 1400' ) )
    # info( net[ 'h4' ].cmd( 'ifconfig h4-eth0 mtu 1400' ) )

    # info( net[ 's1' ].cmd( 'ovs-vsctl set bridge s1 stp_enable=true' ) )
    # info( net[ 's2' ].cmd( 'ovs-vsctl set bridge s2 stp_enable=true' ) )
    # info( net[ 's3' ].cmd( 'ovs-vsctl set bridge s3 stp_enable=true' ) )
    # info( net[ 's4' ].cmd( 'ovs-vsctl set bridge s4 stp_enable=true' ) )


    # info( '*** Routing Table on Router:\n' )
    # info( net[ 'r1' ].cmd( 'route' ) )
    # info( '*** Routing Table on Router:\n' )
    # info( net[ 'r2' ].cmd( 'route' ) )
    # info( '*** Running HIPLS on router 1 *** \n')
    # info( net[ 'r1' ].cmd( 'cd router1 && python3 switchd.py &' ) )
    # info( '*** Running HIPLS on router 2 *** \n')
    # info( net[ 'r2' ].cmd( 'cd router2 && python3 switchd.py &' ) )
    # info( '*** Running HIPLS on router 3 *** \n')
    # info( net[ 'r3' ].cmd( 'cd router3 && python3 switchd.py &' ) )
    # info( '*** Running HIPLS on router 4 *** \n')
    # info( net[ 'r4' ].cmd( 'cd router4 && python3 switchd.py &' ) )
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
