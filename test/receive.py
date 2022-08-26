#!/usr/bin/python3

# coding=utf-8
import socket
server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # 基于网络的数据报协议 UDP
server.bind(('192.168.22.3', 12345))

while True:
    msg,addr=server.recvfrom(1024)
    print(msg,addr)
    server.sendto(msg.upper(),addr)