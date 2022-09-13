fp_ports = ["9/0", "10/0", "11/0", "12/0", "13/0", "14/0", "15/0", "16/0", "17/0", "18/0", "19/0"]

# start ports

for fp_port in fp_ports:
        port, chnl = fp_port.split("/")
        dev_port = pal.port_front_panel_port_to_dev_port_get(int(port), int(chnl))
        pal.port_add(dev_port, pal.port_speed_t.BF_SPEED_100G, pal.fec_type_t.BF_FEC_TYP_NONE)
        pal.port_an_set(dev_port, pal.autoneg_policy_t.BF_AN_FORCE_DISABLE)
        pal.port_enable(dev_port)
    
