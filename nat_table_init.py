worker_num = 4
worker_port = [180, 164, 148, 132]
worker_mac = [0x1070fd190095, 0x1070fd2fd851, 0x1070fd2fe441, 0x1070fd2fd421]
worker_ip = [0xC0A80101, 0xC0A80102, 0xC0A80203, 0xC0A80104]
worker_type = [0, 0, 1, 2] # 0: LAN, 1: WAN, 2: NF
switch_mac = [0x020000000001, 0x020000000001, 0x020000000101, 0x020000000201]

for i in range(worker_num):
    bfrt.nat.pipe.IngressParser.PORT_METADATA.add(worker_port[i], worker_type[i])

'''
try:
    for i in range(worker_num):
        if worker_type[i] == 2:
            bfrt.nat.pipe.Ingress.send_out.forward_to_nf_table.set_default_with_l3_forward(worker_port[i])
            #bfrt.nat.pipe.Ingress.send_out.forward_to_nf_table.set_default_with_l3_forward(worker_port[i], 0x020000000001, 0x020000000002)
except:
    print("Cannot load forward_to_nf_table.")

try:
    for i in range(worker_num):
        bfrt.nat.pipe.Ingress.send_out.l2_forward_table.add_with_l2_forward(worker_mac[i], worker_port[i])
except:
    print("Cannot load l2_forward_table.")

try:
    for i in range(worker_num):
        bfrt.nat.pipe.Ingress.send_out.l3_forward_table.add_with_l3_forward(worker_ip[i], worker_port[i])
        #bfrt.nat.pipe.Ingress.send_out.l3_forward_table.add_with_l3_forward(worker_ip[i], worker_port[i], switch_mac[i], worker_mac[i])
    #bfrt.nat.pipe.Ingress.send_out.l3_forward_table.set_default_with_l3_forward(worker_port[3], switch_mac[3], worker_mac[3])
    bfrt.nat.pipe.Ingress.send_out.l3_forward_table.set_default_with_l3_forward(worker_port[3])
except:
    print("Cannot load l3_forward_table.")
'''

try:
    # smaller value means higher priority
    for i in range(worker_num):
        if worker_type[i] != 2: # not to NF
            bfrt.nat.pipe.Egress.mac_table.add_with_set_mac(0, 0xC, worker_ip[i], 0xffffffff, 1, switch_mac[i], worker_mac[i])
        else: # 4,5,6 (7 has been dropped)
            bfrt.nat.pipe.Egress.mac_table.add_with_set_mac(4, 0xC, 0, 0x0, 1, switch_mac[i], worker_mac[i])
except:
    print("Cannot load mac_table.")

try:
    # smaller value means higher priority
    for i in range(worker_num):
        if worker_type[i] == 1: # to WAN, transition_type == 0/2
            bfrt.nat.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(0, 0xD, 1, 0x1, 0, 0x1, 0, 0x0, worker_ip[i], 0xffffffff, 0, 0x0, 1, worker_port[i])
        if worker_type[i] == 0: # to LAN, transition_type == 1/3
            bfrt.nat.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(1, 0xD, 1, 0x1, 0, 0x1, 0, 0x0, 0, 0x0, worker_ip[i], 0xffffffff, 1, worker_port[i])
        if worker_type[i] == 2: # transition_type == 0/1/6 (0,1 is mismatch)
            bfrt.nat.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(0, 0x0, 0, 0x0, 0, 0x0, 0, 0x0, 0, 0x0, 0, 0x0, 2, worker_port[i])
        # transition_type == 8
        bfrt.nat.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(8, 0xF, 0, 0x0, 0, 0x0, worker_mac[i], 0xffffffffffff, 0, 0x0, 0, 0x0, 1, worker_port[i])
    # transition_type == 7
    bfrt.nat.pipe.Ingress.send_out.forward_table.add_with_drop(7, 0xF, 0, 0x0, 0, 0x0, 0, 0x0, 0, 0x0, 0, 0x0, 1)
    

except:
    print("Cannot load forward_table.")

crc_poly = 0x04C11DB7
crc_init = 0x00000000
crc_xor = 0x00000000

# 有点奇怪，如果不用global，初始化列表中调用就找不到，但在其他地方可以直接调用，按理说应该都能直接调的
global crc32_bit

def crc32_bit(data, len):
    global crc_poly
    crc_bit_value = [0, crc_poly]
    res = 0
    for i in range(len-1, -1, -1):
        res = (res << 1 & 0xffffffff) ^ crc_bit_value[res >> 31 ^ (data >> i & 1)]
    return res

crc_value = [crc32_bit(x, 8) for x in range(256)]

def crc32(data, len_in_byte):
    global crc_poly
    global crc_init
    global crc_xor
    global crc_value
    res = crc_init
    data_bytes = data.to_bytes(len_in_byte, "big")
    for i in range(len_in_byte):
        res = (res << 8 & 0xffffffff) ^ crc_value[res >> 24 ^ data_bytes[i]]
    return res ^ crc_xor


wan_addr_base = 0xC0A802FE
min_port = 30000
total_flow_num = 1 << 21
switch_flow_num = 1 << 17
switch_flow_num_per_reg = 1 << 16
port_num_per_addr = (1 << 16) - min_port

# 不仅python需要改，nf.cpp也需要改初始化的过程。
try:
    bitmap = 0
    num_set = 0
    for i in range(0, total_flow_num):
        if i % 20000 == 0:
            print(i)
        if num_set == switch_flow_num:
            break
        addr_offset = i // port_num_per_addr
        wan_addr = wan_addr_base - addr_offset
        wan_port = min_port + i % port_num_per_addr
        index = (switch_flow_num - 1) & crc32(wan_addr << 16 | wan_port, 6)
        if bitmap >> index & 1:
            continue
        bitmap |= 1 << index
        num_set += 1
        index_hi = index // switch_flow_num_per_reg
        index_lo = index % switch_flow_num_per_reg
        eval("bfrt.nat.pipe.Ingress.kv{}.val1.add(index_lo, wan_addr)".format(index_hi))
        eval("bfrt.nat.pipe.Ingress.kv{}.val0.add(index_lo, wan_port)".format(index_hi))

    for i in range(0, switch_flow_num//switch_flow_num_per_reg):
        eval("bfrt.nat.pipe.Ingress.kv{}.val1.operation_register_sync()".format(i))
        eval("bfrt.nat.pipe.Ingress.kv{}.val0.operation_register_sync()".format(i))
except:
    print("Cannot load NAT entries.")
