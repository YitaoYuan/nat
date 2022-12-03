#!/usr/bin/python3

#_*_coding:utf-8_*_

import socket
import time
import sys

if len(sys.argv) != 5:
    print("Usage: python3 send.py <receiver_ip> <receiver_port> <time_interval> <packet_num>")
    sys.exit(1)

ip = sys.argv[1]
port = int(sys.argv[2])
dst = (ip, port)
time_int = float(sys.argv[3])
loop_num = int(sys.argv[4])

cnt = 0
loop = 0

for _ in range(loop_num):
    loop = loop + 1
    msg = str(loop)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(msg.encode('utf-8'), dst)
    client.settimeout(time_int)
    try:
        back_msg,addr=client.recvfrom(1024)
        cnt = cnt + 1
        time.sleep(time_int)
        print(back_msg.decode('utf-8'),addr)
    except socket.timeout:
        pass
    except: # CTRL+C
        sys.exit(0)
    print("ACK rate {}/{}".format(cnt, loop))
    
