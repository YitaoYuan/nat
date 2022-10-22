#!/usr/bin/python3

# coding=utf-8
import socket
import sys

if len(sys.argv) != 3:
    print("Usage: python3 receive.py <receiver_ip> <receiver_port>")
    sys.exit(1)

ip = sys.argv[1]
port = int(sys.argv[2])


server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # 基于网络的数据报协议 UDP
server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
server.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((ip, port))


while True:
    msg,addr=server.recvfrom(1024)
    print(msg,addr)
    server.sendto(msg.upper(),addr)
