#!/bin/bash

ID=${1}
IF=enp178s0f0
sudo ifconfig enp178s0f0 192.168.0.${ID}/24 up
sudo ifconfig enp178s0f1 192.168.1.${ID}/24 up

sudo arp -i $IF -s 192.168.0.1 b8:59:9f:1d:04:f2 
sudo arp -i $IF -s 192.168.0.2 b8:59:9f:0b:30:72
sudo arp -i $IF -s 192.168.0.3 98:03:9b:03:46:50
sudo arp -i $IF -s 192.168.0.4 b8:59:9f:02:0d:14
sudo arp -i $IF -s 192.168.0.5 b8:59:9f:b0:2d:50
sudo arp -i $IF -s 192.168.0.6 b8:59:9f:b0:2b:b0
sudo arp -i $IF -s 192.168.0.7 b8:59:9f:b0:2b:b8
sudo arp -i $IF -s 192.168.0.8 b8:59:9f:b0:2d:18
sudo arp -i $IF -s 192.168.0.9 b8:59:9f:b0:2d:58
sudo arp -i $IF -s 192.168.0.21 0c:42:a1:7a:b6:68
sudo arp -i $IF -s 192.168.0.22 0c:42:a1:7a:ca:28