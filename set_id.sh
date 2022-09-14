#!/bin/bash

set -ex

LAN_ADDR=192.168.0
WAN_ADDR=192.168.2
IF=enp178s0f0

ID=$2
LOCAL_NET_ADDR=
REMOTE_NET_ADDR=

if [ '(' "$ID" -ge 0 -a "$ID" -le 9 \) ] # '(' and \( is the same
then
	echo "ID=$ID"
else 
	echo "invalid ID"
	exit
fi

if [ "$1" == "LAN" ]
then 
	LOCAL_NET_ADDR=$LAN_ADDR
	REMOTE_NET_ADDR=$WAN_ADDR
elif [ "$1" == "WAN" ]
then
	LOCAL_NET_ADDR=$WAN_ADDR
	REMOTE_NET_ADDR=$LAN_ADDR
else
	echo "invalid net specify"
	exit
fi

sudo ip addr add $LOCAL_NET_ADDR.$ID dev $IF
sudo ip link set enp178s0f0 up

sudo route del -net $LOCAL_NET_ADDR.0/24
sudo route del -net $REMOTE_NET_ADDR.0/24

sudo route add -net $LOCAL_NET_ADDR.0/24 dev $IF
sudo route add -net $REMOTE_NET_ADDR.0/24 gw $LOCAL_NET_ADDR.254

MAC_PREFIX=
if [ $1 == "LAN" ]
then
	MAC_PREFIX=00:00:00:00:00
else
	MAC_PREFIX=00:00:00:00:01
fi
MAC_TAIL=0$ID

sudo sudo arp -i enp178s0f0 -s $LOCAL_NET_ADDR.254 $MAC_PREFIX:$MAC_TAIL
