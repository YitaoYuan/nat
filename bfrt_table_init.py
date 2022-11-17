worker_num = 4
worker_port = [180, 164, 148, 132]
worker_mac = [0x1070fd190095, 0x1070fd2fd851, 0x1070fd2fe441, 0x1070fd2fd421]
worker_ip = [0xC0A80101, 0xC0A80102, 0xC0A80203, 0xC0A80104]
worker_type = [0, 0, 1, 2] # 0: LAN, 1: WAN, 2: NF
switch_mac = [0x020000000101, 0x020000000101, 0x020000000201, 0x020000000101]

for i in range(worker_num):
    bfrt.nat.pipe.IngressParser.PORT_METADATA.add(worker_port[i], worker_type[i])

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

try:
    # smaller value means higher priority
    for i in range(worker_num):
        bfrt.nat.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(0, 0xC, 1, 0x1, 0, 0x1, 0, 0x0, worker_ip[i], 0xffffffff, 1, worker_port[i])
        bfrt.nat.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(8, 0xF, 0, 0x0, 0, 0x0, worker_mac[i], 0xffffffffffff, 0, 0x0, 2, worker_port[i])
    bfrt.nat.pipe.Ingress.send_out.forward_table.add_with_drop(7, 0xF, 0, 0x0, 0, 0x0, 0, 0x0, 0, 0x0, 3)
    for i in range(worker_num):
        if worker_type[i] == 2:
            bfrt.nat.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(0, 0x0, 0, 0x0, 0, 0x0, 0, 0x0, 0, 0x0, 4, worker_port[i])
except:
    print("Cannot load forward_table.")

wan_addr_base = 0xC0A802FE
min_port = 1 << 15
switch_flow_num = 1 << 17
switch_flow_num_per_reg = 1 << 16
port_num_per_addr = (1 << 16) - min_port

try:
    for i in range(0, switch_flow_num):
        addr_offset = i // port_num_per_addr
        wan_addr = wan_addr_base - addr_offset
        wan_port = min_port + i % port_num_per_addr
        reg_id = i // switch_flow_num_per_reg
        index = i % switch_flow_num_per_reg
        eval("bfrt.nat.pipe.Ingress.kv{}.val1.add(index, wan_addr)".format(reg_id))
        eval("bfrt.nat.pipe.Ingress.kv{}.val0.add(index, wan_port)".format(reg_id))

    for i in range(0, (switch_flow_num-1)//switch_flow_num_per_reg + 1):
        eval("bfrt.nat.pipe.Ingress.kv{}.val1.operation_register_sync()".format(i))
        eval("bfrt.nat.pipe.Ingress.kv{}.val0.operation_register_sync()".format(i))
except:
    print("Cannot load NAT entries.")
