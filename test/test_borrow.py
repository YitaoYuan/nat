#!/usr/bin/python3

import socket
import time
import sys

def usage():
    print("Usage: python3 send.py <receiver_ip> <receiver_port> <aging_time> [-r]")

if len(sys.argv) != 4 and len(sys.argv) != 5:
    usage()
    sys.exit(1)

ip = sys.argv[1]
port = int(sys.argv[2])
dst = (ip, port)
AGING_TIME_S = int(sys.argv[3])
need_ACK = False

if len(sys.argv) == 5:
    if sys.argv[4] == "-r":
        need_ACK = True
    else:
        usage()

over_flow_num = 30 # make sure this number is big enough
extra_hit_time = 10
rest_time = 0.002

client = [socket.socket(socket.AF_INET,socket.SOCK_DGRAM) for i in range(over_flow_num)]
cnt = [0] * over_flow_num

def send_client(i):
    cnt[i] += 1
    snd_msg = "{}-{}".format(i, cnt[i]).encode('utf-8')
    client[i].sendto(snd_msg, dst)
    if need_ACK:
        client[i].settimeout(0.1)
        try:
            recv_msg, addr = client[i].recvfrom(1024)
            if snd_msg != recv_msg and addr != dst:
                print("Unexpected error.")
                sys.exit(1)
        except:
            print("Timeout or other receive other signals.")
            sys.exit(1)
    else:
        time.sleep(rest_time)

# start
send_client(0) # to take up switch's entry
 
time.sleep(3/4 * AGING_TIME_S)

# 3/4
for i in range(1, over_flow_num):
    send_client(i)
for i in range(extra_hit_time):
    send_client(1) # On nf, this flow's entry is not borrowed
for i in range(2 * extra_hit_time):
    send_client(over_flow_num - 1) # On nf, this flow's entry is borrowed

total_rest_time = rest_time * (over_flow_num - 1 + extra_hit_time + 2*extra_hit_time) 
if total_rest_time > 1/4 * AGING_TIME_S:
    print("Unexpected error.")
    sys.exit(1)

time.sleep(1/2 * AGING_TIME_S)
# 5/4
send_client(2) # this will cause nf's update

time.sleep(1/4 * AGING_TIME_S)
# 6/4
send_client(over_flow_num - 1) # this will go to nf, even it is "heavier" than flow 1
send_client(1) # this will not go to nf