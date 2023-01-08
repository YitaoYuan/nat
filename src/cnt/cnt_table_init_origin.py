worker_num = 5
worker_port = [180, 164, 148, 132, 116]
worker_mac = [0x1070fd190095, 0x1070fd2fd851, 0x1070fd2fe441, 0x1070fd2fd421, 0x02000000000f]
worker_ip = [0xC0A80101, 0xC0A80102, 0xC0A80203, 0xC0A80104, 0xC0A80204]
worker_type = [0, 0, 1, 2, 1] # 0: client, 1: server, 2: NF

switch_mac = [0x020000000001, 0x020000000001, 0x020000000101, 0x020000000201, 0x020000000101]

try:
    for i in range(worker_num):
        bfrt.cnt.pipe.IngressParser.PORT_METADATA.add(worker_port[i], worker_type[i]) 
    # for worker5 this will fail
except:
    print("Cannot load PORT_METADATA.")

try:
    # Althogh our code support multiple load-balance set,
    # we only use one set for test.
    for i in range(worker_num):
        if worker_type[i] != 2: # not to NF
            bfrt.cnt.pipe.Egress.mac_table.add_with_set_mac(0, 0xC, worker_ip[i], 0xffffffff, 1, switch_mac[i], worker_mac[i])
        else: # 4,5,6 (7 has been dropped)
            bfrt.cnt.pipe.Egress.mac_table.add_with_set_mac(4, 0xC, 0, 0x0, 1, switch_mac[i], worker_mac[i])
except:
    print("Cannot load mac_table.")

try:
    # smaller value means higher priority
    for i in range(worker_num):
        if worker_type[i] == 1: # to server, transition_type == 0/2
            bfrt.cnt.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(0, 0xF, 1, 0x1, worker_ip[i], 0xffffffff, 1, worker_port[i])
            bfrt.cnt.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(2, 0xF, 0, 0x0, worker_ip[i], 0xffffffff, 1, worker_port[i])
        if worker_type[i] == 0: # to client, transition_type == 1/3
            bfrt.cnt.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(1, 0xF, 1, 0x1, worker_ip[i], 0xffffffff, 1, worker_port[i])
            bfrt.cnt.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(3, 0xF, 0, 0x0, worker_ip[i], 0xffffffff, 1, worker_port[i])
        if worker_type[i] == 2: # transition_type == 0/1/6 (0,1 is mismatch)
            bfrt.cnt.pipe.Ingress.send_out.forward_table.add_with_set_egress_port(0, 0x0, 0, 0x0, 0, 0x0, 2, worker_port[i])
    # transition_type == 7
    bfrt.cnt.pipe.Ingress.send_out.forward_table.add_with_drop(7, 0xF, 0, 0x0, 0, 0x0, 1)
except:
    print("Cannot load forward_table.")

