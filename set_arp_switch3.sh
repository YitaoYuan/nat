#!/bin/bash

DIR=$(dirname $0)
. $DIR/utils.sh

IF=ens10f1

echo_r "sudo arp -i $IF -s 192.168.1.1 10:70:fd:19:00:95"
echo_r "sudo arp -i $IF -s 192.168.1.2 10:70:fd:2f:d8:51"
echo_r "sudo arp -i $IF -s 192.168.1.3 10:70:fd:2f:e4:41"
echo_r "sudo arp -i $IF -s 192.168.1.4 10:70:fd:2f:d4:21"
