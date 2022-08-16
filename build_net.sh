#!/bin/bash

set -e

CMD_PREFIX="ip netns exec sw"

IP_PREFIX="192.168"
NET1=$IP_PREFIX".11"
NET2=$IP_PREFIX".22"

ip -all netns del

#hosts
ip netns add h1
ip netns add h2
ip netns add h3
ip netns add h4
ip netns add h5
ip netns add h6
ip netns add sw

#switches
$CMD_PREFIX  brctl addbr sw1
$CMD_PREFIX  brctl addbr sw2

#links
$CMD_PREFIX  ip link add h1i1 type veth peer name sw1i1
$CMD_PREFIX  ip link add h2i1 type veth peer name sw1i2

$CMD_PREFIX  ip link add h5i1 type veth peer name sw1i3

$CMD_PREFIX  ip link add h3i1 type veth peer name sw2i1
$CMD_PREFIX  ip link add h4i1 type veth peer name sw2i2

$CMD_PREFIX  ip link add h5i2 type veth peer name sw2i3

$CMD_PREFIX  ip link add h5i3 type veth peer name h6i1

#plug in interfaces 
$CMD_PREFIX  ip link set h1i1 netns h1
$CMD_PREFIX  ip link set h2i1 netns h2
$CMD_PREFIX  ip link set h3i1 netns h3
$CMD_PREFIX  ip link set h4i1 netns h4
$CMD_PREFIX  ip link set h5i1 netns h5
$CMD_PREFIX  ip link set h5i2 netns h5
$CMD_PREFIX  ip link set h5i3 netns h5
$CMD_PREFIX  ip link set h6i1 netns h6

$CMD_PREFIX  brctl addif sw1 sw1i1
$CMD_PREFIX  brctl addif sw1 sw1i2
$CMD_PREFIX  brctl addif sw1 sw1i3
$CMD_PREFIX  brctl addif sw2 sw2i1
$CMD_PREFIX  brctl addif sw2 sw2i2
$CMD_PREFIX  brctl addif sw2 sw2i3

#config ip address
ip netns exec h1 ip addr add $NET1.1 dev h1i1
ip netns exec h2 ip addr add $NET1.2 dev h2i1

ip netns exec h3 ip addr add $NET2.3 dev h3i1
ip netns exec h4 ip addr add $NET2.4 dev h4i1

ip netns exec h5 ip addr add $NET1.5 dev h5i1
ip netns exec h5 ip addr add $NET2.5 dev h5i2
# it is not necessary to allocate IP address for h6i1 & h5i3

#config mac address
ip netns exec h1 ifconfig h1i1 hw ether 00:00:00:00:01:01
ip netns exec h2 ifconfig h2i1 hw ether 00:00:00:00:02:01
ip netns exec h3 ifconfig h3i1 hw ether 00:00:00:00:03:01
ip netns exec h4 ifconfig h4i1 hw ether 00:00:00:00:04:01
ip netns exec h5 ifconfig h5i1 hw ether 00:00:00:00:05:01
ip netns exec h5 ifconfig h5i2 hw ether 00:00:00:00:05:02
ip netns exec h5 ifconfig h5i3 hw ether 00:00:00:00:05:03
ip netns exec h6 ifconfig h6i1 hw ether 00:00:00:00:06:01

#set up 
$CMD_PREFIX  ip link set sw1 up
$CMD_PREFIX  ip link set sw2 up

ip netns exec h1 ip link set lo up
ip netns exec h1 ip link set h1i1 up

ip netns exec h2 ip link set lo up
ip netns exec h2 ip link set h2i1 up

ip netns exec h3 ip link set lo up
ip netns exec h3 ip link set h3i1 up

ip netns exec h4 ip link set lo up
ip netns exec h4 ip link set h4i1 up

ip netns exec h5 ip link set lo up
ip netns exec h5 ip link set h5i1 up
ip netns exec h5 ip link set h5i2 up
ip netns exec h5 ip link set h5i3 up

ip netns exec h6 ip link set lo up
ip netns exec h6 ip link set h6i1 up

$CMD_PREFIX  ip link set sw1i1 up 
$CMD_PREFIX  ip link set sw1i2 up 
$CMD_PREFIX  ip link set sw1i3 up

$CMD_PREFIX  ip link set sw2i1 up 
$CMD_PREFIX  ip link set sw2i2 up 
$CMD_PREFIX  ip link set sw2i3 up 

#route
ip netns exec h1 route add -net $NET1.0/24 metric 100 dev h1i1
ip netns exec h2 route add -net $NET1.0/24 metric 100 dev h2i1
ip netns exec h5 route add -net $NET1.0/24 metric 100 dev h5i1

ip netns exec h3 route add -net $NET2.0/24 metric 100 dev h3i1
ip netns exec h4 route add -net $NET2.0/24 metric 100 dev h4i1
ip netns exec h5 route add -net $NET2.0/24 metric 100 dev h5i2

ip netns exec h1 route add -net default gw $NET1.5 metric 200 
ip netns exec h2 route add -net default gw $NET1.5 metric 200 

ip netns exec h3 route add -net default gw $NET2.5 metric 200 
ip netns exec h4 route add -net default gw $NET2.5 metric 200 

#turn off h5's forward
ip netns exec h5 sysctl net.ipv4.ip_forward=0

#turn off tcp offloading
ip netns exec h1 ethtool -K h1i1 tx off
ip netns exec h2 ethtool -K h2i1 tx off
ip netns exec h3 ethtool -K h3i1 tx off
ip netns exec h4 ethtool -K h4i1 tx off
ip netns exec h5 ethtool -K h5i1 tx off
ip netns exec h5 ethtool -K h5i2 tx off
ip netns exec h5 ethtool -K h5i3 tx off
ip netns exec h6 ethtool -K h6i1 tx off


