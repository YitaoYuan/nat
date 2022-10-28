#!/bin/bash

set -e

LAN_ADDR=192.168.1
WAN_ADDR=192.168.2
IF=ens10f1

ID=$2
LOCAL_NET_ADDR=
REMOTE_NET_ADDR=

MAC_PREFIX=01:23:45:67:89

if [ '(' "$ID" -ge 0 -a "$ID" -le 9 \) ] # '(' and \( is the same
then
	: # pass
else 
	echo "invalid ID"
	exit
fi

if [ "$1" == "LAN" ]
then 
	LOCAL_NET_ADDR=$LAN_ADDR
	REMOTE_NET_ADDR=$WAN_ADDR
	MAC_TAIL=01
elif [ "$1" == "WAN" ]
then
	LOCAL_NET_ADDR=$WAN_ADDR
	REMOTE_NET_ADDR=$LAN_ADDR
	MAC_TAIL=02
else
	echo "invalid net specify"
	exit
fi

(
set -x
sudo ip link set $IF down # this will clear route && arp entries related to $IF
sudo ifconfig $IF $LOCAL_NET_ADDR.$ID netmask 255.255.255.0
sudo ip link set $IF up 
)

set +e #grep will return 1 on mismatch
route1=`route | grep -E "$LOCAL_NET_ADDR\.0"`
route2=`route | grep -E "$REMOTE_NET_ADDR\.0"`
arp1=`arp | grep -E "$LOCAL_NET_ADDR\.254"`
arp2=`arp | grep -E "$REMOTE_NET_ADDR\.254"`
set -e

if [ -n "$route1" ]
then 
    (
    set -x 
    sudo route del -net $LOCAL_NET_ADDR.0/24
    )
fi

if [ -n "$route2" ]
then
    (
    set -x
    sudo route del -net $REMOTE_NET_ADDR.0/24
    )
fi

if [ -n "$arp1" ]
then
    (
    set -x 
    sudo arp -i $IF -d $LOCAL_NET_ADDR.254
    )
fi

if [ -n "$arp2" ]
then
    (
    set -x
    sudo arp -i $IF -d $REMOTE_NET_ADDR.254
    )
fi
	
(
set -x
sudo route add -net $LOCAL_NET_ADDR.0/24 dev $IF
)

if [ "$1" == "LAN" ]
then
    (
    set -x
    sudo route add -net $REMOTE_NET_ADDR.0/24 gw $LOCAL_NET_ADDR.254
    )
fi

(
set -x
sudo arp -i $IF -s $LOCAL_NET_ADDR.254 $MAC_PREFIX:$MAC_TAIL
)
