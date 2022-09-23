#!/usr/bin/python3

#_*_coding:utf-8_*_

import socket
import sys

if len(sys.argv) != 3:
    print("Usage: python3 send.py <receiver_ip> <receiver_port>")
    sys.exit(1)

ip = sys.argv[1]
port = int(sys.argv[2])

client=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    msg=input('>>: ').strip()
    if not msg:continue

    client.sendto(msg.encode('utf-8'),(ip, port))

    back_msg,addr=client.recvfrom(1024)
    print(back_msg.decode('utf-8'), addr)

