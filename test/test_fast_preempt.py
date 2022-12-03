#!/usr/bin/python3

import socket
import time
import sys

if len(sys.argv) != 4:
    print("Usage: python3 send.py <receiver_ip> <receiver_port> <aging_time>")
    sys.exit(1)

ip = sys.argv[1]
port = int(sys.argv[2])
dst = (ip, port)
AGING_TIME_S = int(sys.argv[3])

client1=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
client2=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
client3=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
client4=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)



#0
client1.sendto("1-1".encode('utf-8'), dst)
time.sleep(AGING_TIME_S/8)
#1/8
client2.sendto("2-1".encode('utf-8'), dst)
time.sleep(AGING_TIME_S/8)
#1/4
client3.sendto("3-1".encode('utf-8'), dst)
time.sleep(0.01)
client3.sendto("3-2".encode('utf-8'), dst)
time.sleep(0.01)
client2.sendto("2-2".encode('utf-8'), dst)
time.sleep(0.01)
client1.sendto("1-2".encode('utf-8'), dst)


