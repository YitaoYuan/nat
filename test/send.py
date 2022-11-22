#!/usr/bin/python3

#_*_coding:utf-8_*_

import socket
import sys

if len(sys.argv) != 3:
    print("Usage: python3 send.py <receiver_ip> <receiver_port>")
    sys.exit(1)

ip = sys.argv[1]
port = int(sys.argv[2])
dst = (ip, port)

client=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)

while True:
    msg=input('>>: ').strip()
    if not msg:continue

    client.settimeout(1)
    cnt = 0
    while cnt < 2:
        try:
            client.sendto(msg.encode('utf-8'), dst)
            cnt = cnt + 1
            back_msg,addr=client.recvfrom(1024)
            print(back_msg.decode('utf-8'), addr)
            break
        except socket.timeout:
            pass
        except:
            sys.exit(0)
    
    

