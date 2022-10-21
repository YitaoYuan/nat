#!/bin/bash

set -e

LAN_ADDR=192.168.1
WAN_ADDR=192.168.2
IF=ens10f1

ID=$2
LOCAL_NET_ADDR=
REMOTE_NET_ADDR=

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
sudo ip link set $IF down
sudo ifconfig $IF $LOCAL_NET_ADDR.$ID netmask 255.255.255.0
#sudo ip addr replace $LOCAL_NET_ADDR.$ID dev $IF #replace = add or change
sudo ip link set $IF up
)

set +e #grep will return 1 on mismatch
route1=`route | grep -E "$LOCAL_NET_ADDR\.0(\s+)0\.0\.0\.0(\s+)255\.255\.255\.0"`
route2=`route | grep -E "$REMOTE_NET_ADDR\.0(\s+)$LOCAL_NET_ADDR\.254(\s+)255\.255\.255\.0"`
set -e

if [ -z "$route1" ]
then 
	(
	set -x
	sudo route add -net $LOCAL_NET_ADDR.0/24 dev $IF
	)
else
	echo "Already have route entry: $LOCAL_NET_ADDR.0/24"
fi

if [ -z "$route2" ]
then
	(
	set -x
	sudo route add -net $REMOTE_NET_ADDR.0/24 gw $LOCAL_NET_ADDR.254
	)
else
	echo "Already have route entry: $REMOTE_NET_ADDR.0/24 gw $LOCAL_NET_ADDR.254"
fi

MAC_PREFIX=01:23:45:67:89

(
set -x
sudo arp -i $IF -s $LOCAL_NET_ADDR.254 $MAC_PREFIX:$MAC_TAIL
)

#(
#set -x
#sudo ethtool -K $IF tx off 
#)
