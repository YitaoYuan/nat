#!/usr/bin/python3

#_*_coding:utf-8_*_

import socket

client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

while True:
    msg=input('>>: ').strip()
    if not msg:continue

    client.sendto(msg.encode('utf-8'),('192.168.22.3', 12345))

    back_msg,addr=client.recvfrom(1024)
    print(back_msg.decode('utf-8'),addr)