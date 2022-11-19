#!/bin/bash

DIR=$(dirname $0)
. $DIR/utils.sh

set -e

LAN_ADDR=192.168.1
WAN_ADDR=192.168.2
IF=ens10f1

ID=$2
LOCAL_NET_ADDR=
REMOTE_NET_ADDR=

MAC_PREFIX=02:00:00:00

if [ '(' "$ID" -ge 0 -a "$ID" -le 9 \) ] # '(' and \( is the same
then
	: # pass
else 
	echo_e "invalid ID"
	exit
fi

if [ "$1" == "LAN" ]
then 
	LOCAL_NET_ADDR=$LAN_ADDR
	REMOTE_NET_ADDR=$WAN_ADDR
	MAC_TAIL=00:01
elif [ "$1" == "WAN" ]
then
	LOCAL_NET_ADDR=$WAN_ADDR
	REMOTE_NET_ADDR=$LAN_ADDR
	MAC_TAIL=01:01
else
	echo_e "invalid net specify"
	exit
fi

echo_r "sudo ip link set $IF down" # this will clear route && arp entries related to $IF
echo_r "sudo ifconfig $IF $LOCAL_NET_ADDR.$ID netmask 255.255.255.0"
echo_r "sudo ip link set $IF up"

set +e #grep will return 1 on mismatch
route1=`route | grep -E "$LOCAL_NET_ADDR\.0"`
set -e

if [ -n "$route1" ]
then 
    echo_r "sudo route del -net $LOCAL_NET_ADDR.0/24"
fi

echo_r "sudo route add -net $LOCAL_NET_ADDR.0/24 dev $IF"

if [ "$1" == "LAN" ]
then
    echo_r "sudo route add -net $REMOTE_NET_ADDR.0/24 gw $LOCAL_NET_ADDR.254"
	echo_r "sudo arp -i $IF -s $LOCAL_NET_ADDR.254 $MAC_PREFIX:$MAC_TAIL"
else
	for i in {128..254}
	do 
		echo_r "sudo arp -i $IF -s $LOCAL_NET_ADDR.$i $MAC_PREFIX:$MAC_TAIL"
	done
fi





