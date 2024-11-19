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
        # spoke2 = self.addNode( 'sp2', cls=LinuxRouter )
        # spoke3 = self.addNode( 'sp3', cls=LinuxRouter )

        switch1 = self.addSwitch( 'sw1', cls=OVSKernelSwitch)
        # switch2 = self.addSwitch( 'sw2', cls=OVSKernelSwitch)
        # switch3 = self.addSwitch( 'sw3', cls=OVSKernelSwitch)
        switch4 = self.addSwitch( 'sw4', cls=OVSKernelSwitch)

        self.addLink(switch4, hub1, intfName2='hu1-eth1',
                                params2={ 'ip' : '192.168.3.1/29' })
        self.addLink(switch4, hub2, intfName2='hu2-eth1',
                                params2={ 'ip' : '192.168.3.2/29' })
        self.addLink(switch4, hub3, intfName2='hu3-eth1',
                                params2={ 'ip' : '192.168.3.3/29' })

        self.addLink(hub1, switch1, intfName1='hu1-eth0', params1={ 'ip' : '192.168.1.1/24'}) #/24?? ,
        self.addLink(switch1, spoke1, #Nått fel med spoke
                intfName2='sp1-eth1', params2={ 'ip' : '192.168.1.4/24'} ) #/24??? 192.168.3.4?? ,
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
    info( net[ 'hu1' ].cmd( 'ifconfig hu1-eth1 192.168.3.1 netmask 255.255.255.248') )
    info( net[ 'hu2' ].cmd( 'ifconfig hu2-eth1 192.168.3.2 netmask 255.255.255.248' ) )
    info( net[ 'hu3' ].cmd( 'ifconfig hu3-eth1 192.168.3.3 netmask 255.255.255.248' ) )
    info( net[ 'sp1' ].cmd( 'ifconfig sp1-eth1 192.168.1.4 netmask 255.255.255.0' ) )
    info( net[ 'hu1' ].cmd( 'ifconfig hu1-eth0 192.168.1.1 netmask 255.255.255.0'))

    info( net[ 'hu1' ].cmd( '/sbin/ethtool -K hu1-eth0 rx off tx off sg off' ) )
    info( net[ 'hu1' ].cmd( '/sbin/ethtool -K hu1-eth1 rx off tx off sg off' ) )
    info( net[ 'hu2' ].cmd( '/sbin/ethtool -K hu2-eth0 rx off tx off sg off' ) )
    info( net[ 'hu2' ].cmd( '/sbin/ethtool -K hu2-eth1 rx off tx off sg off' ) )
    info( net[ 'hu3' ].cmd( '/sbin/ethtool -K hu3-eth0 rx off tx off sg off' ) )
    info( net[ 'hu3' ].cmd( '/sbin/ethtool -K hu3-eth1 rx off tx off sg off' ) )
    # info( net[ 'sp1' ].cmd( '/sbin/ethtool -K sp1-eth0 rx off tx off sg off' ) )
    info( net[ 'sp1' ].cmd( '/sbin/ethtool -K sp1-eth1 rx off tx off sg off' ) )

    # net['hu1'].cmd('ip route add 192.168.1.4/24 via 192.168.3.4 dev hu1-eth1')
    # net['hu2'].cmd('ip route add 192.168.1.4/24 via 192.168.3.4 dev hu2-eth1')
    # net['hu3'].cmd('ip route add 192.168.1.4/24 via 192.168.3.4 dev hu3-eth1')
    net['sp1'].cmd('ip route add 192.168.3.0/29 via 192.168.1.1 dev sp1-eth1')

    # Disable offloading (to avoid Mininet quirks)
    for router in ['hu1', 'hu2', 'hu3', 'sp1']:
        for iface in ['eth0', 'eth1']:
            net[router].cmd(f'/sbin/ethtool -K {router}-{iface} rx off tx off sg off')


    # info( net[ 'h1' ].cmd( 'ifconfig h1-eth0 mtu 1400' ) )
    # info( net[ 'h2' ].cmd( 'ifconfig h2-eth0 mtu 1400' ) )
    # info( net[ 'h3' ].cmd( 'ifconfig h3-eth0 mtu 1400' ) )
    # info( net[ 'h4' ].cmd( 'ifconfig h4-eth0 mtu 1400' ) )

    # info( net[ 'sw1' ].cmd( 'ovs-vsctl set bridge sw1 stp_enable=true' ) ) ???onödig???
    # info( net[ 'sw2' ].cmd( 'ovs-vsctl set bridge sw2 stp_enable=true' ) )
    # info( net[ 'sw3' ].cmd( 'ovs-vsctl set bridge sw3 stp_enable=true' ) )
    # info( net[ 'sw4' ].cmd( 'ovs-vsctl set bridge sw4 stp_enable=true' ) )


    info( '*** Routing Table on Router:\n' )
    info( net[ 'hu1' ].cmd( 'route -n' ) )
    info( net[ 'hu2' ].cmd( 'route -n' ) )
    info( net[ 'hu3' ].cmd( 'route -n' ) )
    info( net[ 'sp1' ].cmd( 'route -n' ) )
    info('*** Testing connectivity ***\n')
    info(net['hu1'].cmd('ping -c 3 192.168.3.2'))  # Test hu1 to hu2
    info(net['hu1'].cmd('ping -c 3 192.168.3.3'))  # Test hu1 to hu3
    info(net['sp1'].cmd('ping -c 3 192.168.1.1'))  # Test sp1 to hu1
    info(net['hu1'].cmd('ping -c 3 192.168.1.4'))  # Test hu1 to sp1
    # info( '*** Running HIPLS on router 1 *** \n') 
    # info( net[ 'hu1' ].cmd( 'cd hub1 && python3 switchd.py &' ) )
    # info( '*** Running HIPLS on router 2 *** \n')
    # info( net[ 'hu2' ].cmd( 'cd hub2 && python3 switchd.py &' ) )
    # info( '*** Running HIPLS on router 3 *** \n')
    # info( net[ 'hu3' ].cmd( 'cd hub3 && python3 switchd.py &' ) )
    # info( '*** Running HIPLS on router 4 *** \n')
    # info( net[ 'sp1' ].cmd( 'cd spoke1 && python3 switchd.py &' ) )
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
