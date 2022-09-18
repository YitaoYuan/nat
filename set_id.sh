#!/bin/bash

set -e

LAN_ADDR=192.168.0
WAN_ADDR=192.168.2
IF=enp178s0f0

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
elif [ "$1" == "WAN" ]
then
	LOCAL_NET_ADDR=$WAN_ADDR
	REMOTE_NET_ADDR=$LAN_ADDR
else
	echo "invalid net specify"
	exit
fi

(
set -x
sudo ip addr replace $LOCAL_NET_ADDR.$ID dev $IF #replace = add or change
sudo ip link set enp178s0f0 up
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

MAC_PREFIX=
if [ $1 == "LAN" ]
then
	MAC_PREFIX=00:00:00:00:00
else
	MAC_PREFIX=00:00:00:00:01
fi
MAC_TAIL=0$ID

(
set -x
sudo sudo arp -i enp178s0f0 -s $LOCAL_NET_ADDR.254 $MAC_PREFIX:$MAC_TAIL
)
