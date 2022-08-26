#!/usr/bin/python3

import socket
import time

client1=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
client2=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

AGING_TIME_S = 10
msg="123"
#0
client1.sendto("1-1".encode('utf-8'),('192.168.22.3', 12345))
time.sleep(AGING_TIME_S/4)
#1/4
client2.sendto("2-1".encode('utf-8'),('192.168.22.3', 12345))
time.sleep(AGING_TIME_S/2)
#3/4
client2.sendto("2-2".encode('utf-8'),('192.168.22.3', 12345))
time.sleep(AGING_TIME_S/2)
#5/4 
#触发更新
client2.sendto("2-3".encode('utf-8'),('192.168.22.3', 12345))
time.sleep(AGING_TIME_S/2)
#7/4
#不会被送到nfv
client2.sendto("2-4".encode('utf-8'),('192.168.22.3', 12345))

