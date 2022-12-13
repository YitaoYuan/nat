worker_num = 4
worker_port = [180, 164, 148, 132]
worker_mac = [0x1070fd190095, 0x1070fd2fd851, 0x1070fd2fe441, 0x1070fd2fd421]
worker_ip = [0xC0A80101, 0xC0A80102, 0xC0A80203, 0xC0A80104]
worker_type = [1, 1, 0, 2] # 0: client, 1: server, 2: NF
switch_mac = [0x020000000001, 0x020000000001, 0x020000000101, 0x020000000201]
lb_sets = [(0xC0A802FE, [worker_ip[0], worker_ip[1]], 32)]
#lb_sets = [(0xC0A802FE, [worker_ip[0]], 16), (0xC0A802FD, [worker_ip[1]], 64)]

crc_poly1 = 0x04C11DB7
crc_poly2 = 0x1EDC6F41

# 有点奇怪，如果不用global，初始化列表中调用就找不到，但在其他地方可以直接调用，按理说应该都能直接调的
global crc32_bit
def crc32_bit(data, len, crc_poly):
    crc_bit_value = [0, crc_poly]
    res = 0
    for i in range(len-1, -1, -1):
        res = (res << 1 & 0xffffffff) ^ crc_bit_value[res >> 31 ^ (data >> i & 1)]
    return res


# use Maglev hashing
global install_lb_set
def install_lb_set(vip, server_ip, table_size):
    global crc_poly1
    global crc_poly2
    assert((table_size & -table_size) == table_size) # table_size == 2**x
    for ip in server_ip:
        bfrt.lb.pipe.Egress.vip_table.add_with_get_vip(ip, vip)
    bfrt.lb.pipe.Ingress.lb_hash_mask_table.add_with_get_hash_mask(vip, table_size-1)
    bitmap = 0
    install_num = 0
    offset = [crc32_bit(ip, 32, crc_poly1) % table_size for ip in server_ip]
    step = [crc32_bit(ip, 32, crc_poly2) % (table_size//2) * 2 + 1 for ip in server_ip]
    # gcd(step[i], table_size) == 1
    while True:
        for i in range(len(server_ip)):
            while bitmap >> offset[i] & 1:
                offset[i] = (offset[i] + step[i]) % table_size
            bitmap |= 1 << offset[i]
            install_num += 1
            bfrt.lb.pipe.Ingress.lb_table.add_with_get_server_addr(vip, offset[i], server_ip[i])
            if install_num == table_size:
                return
    

for i in range(worker_num):
    bfrt.lb.pipe.IngressParser.PORT_METADATA.add(worker_port[i], worker_type[i])

try:
    # Althogh our code support multiple load-balance set,
    # we only use one set for test.
    for i in range(worker_num):
        if worker_type[i] != 2: # not to NF
            bfrt.lb.pipe.Egress.mac_table.add_with_set_mac(0, 0xC, worker_ip[i], 0xffffffff, 1, switch_mac[i], worker_mac[i])
        else: # 4,5,6 (7 has been dropped)
            bfrt.lb.pipe.Egress.mac_table.add_with_set_mac(4, 0xC, 0, 0x0, 1, switch_mac[i], worker_mac[i])
except:
    print("Cannot load mac_table.")

try:
    # smaller value means higher priority
    for i in range(worker_num):
        if worker_type[i] == 1: # to server, transition_type == 0/2
            bfrt.lb.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(0, 0xD, 1, 0x1, worker_ip[i], 0xffffffff, 0, 0x0, 1, worker_port[i])
        if worker_type[i] == 0: # to client, transition_type == 1
            bfrt.lb.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(1, 0xF, 0, 0x0, 0, 0x0, worker_ip[i], 0xffffffff, 1, worker_port[i])
        if worker_type[i] == 2: # transition_type == 0/1/6 (0,1 is mismatch)
            bfrt.lb.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(0, 0x0, 0, 0x0, 0, 0x0, 0, 0x0, 2, worker_port[i])
    # transition_type == 7
    bfrt.lb.pipe.Ingress.send_out.forward_table.add_with_drop(7, 0xF, 0, 0x0, 0, 0x0, 0, 0x0, 1)
    # bfrt.lb.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(6, 0xF, 0, 0x0, 0, 0x0, 0, 0x0, 1, worker_port[2])
except:
    print("Cannot load forward_table.")

try:
    # Althogh our code support multiple load-balance set,
    # we only use one set for test.
    for vip, server_ip, table_size in lb_sets:
        install_lb_set(vip, server_ip, table_size)
except:
    print("Cannot load load-balance table.")

