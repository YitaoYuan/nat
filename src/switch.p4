/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
#include "shared_metadata.h"

typedef bit<9>  egress_spec_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ip4_addr_t;
typedef bit<16> port_t;
typedef bit<16> index_t;
typedef bit<32> time_t;
typedef bit<8> version_t;

const bit<9>  NFV_PORT = 2;

const bit<8>  TCP_PROTOCOL = 0x06;
const bit<8>  UDP_PROTOCOL = 0x11;
const bit<8>  ICMP_PROTOCOL = 0x01;

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_METADATA = SHARED_TYPE_METADATA;

//you can change these by tables to support dynamic & multiple LAN address allocation
const ip4_addr_t LAN_ADDR = SHARED_LAN_ADDR;// 192.168.0.0
const ip4_addr_t LAN_ADDR_MASK = SHARED_LAN_ADDR_MASK;// /24
const ip4_addr_t NAT_ADDR = SHARED_NAT_ADDR;// 192.168.2.254

const port_t PORT_MIN = SHARED_PORT_MIN;
const bit<32> PORT_MAX = SHARED_PORT_MAX;//65536;// not included
const port_t SWITCH_PORT_NUM = SHARED_SWITCH_PORT_NUM;//50000;
const port_t NFV_PORT_NUM = (port_t)(PORT_MAX - (bit<32>)PORT_MIN) - SWITCH_PORT_NUM;

const time_t AGING_TIME_US = SHARED_AGING_TIME_US;// 1 s

const mac_addr_t SWITCH_INNER_MAC = SHARED_SWITCH_INNER_MAC;
const mac_addr_t NFV_INNER_MAC = SHARED_NFV_INNER_MAC;

const time_t FOREVER_TIMEOUT = 32w0xC0000000;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>   ether_type;
}

header nat_metadata_t {//36
    ip4_addr_t  src_addr;
    ip4_addr_t  dst_addr;
    port_t      src_port;
    port_t      dst_port;
    bit<8>      protocol;
    bit<8>      zero1;

    port_t      switch_port;
    version_t   version;

    bit<8>      type;// 8w0b100_00000 to_in, 8w0b010_00000 to_out, 8w0b001_00000 update, 

    

    index_t     index; // index is the hash value of flow id
    time_t      nfv_time;// 因为一个ACK返回的时候wait_entry可能已经没了，所以时间需要记录在packet里
    bit<16>     checksum;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    unused1;
    bit<16>   total_length;
    bit<32>   unused2;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   checksum;
    ip4_addr_t src_addr;
    ip4_addr_t dst_addr;
}

struct ipv4_flow_id_t { // size == 14
    ip4_addr_t   src_addr;
    ip4_addr_t   dst_addr;
    port_t      src_port;
    port_t      dst_port;
    bit<8>      protocol;
    bit<8>      zero;// zero == 0x00, for alignment in C
}

header tcp_t{
    port_t src_port;
    port_t dst_port;
    bit<96> unused1;
    bit<16> checksum;
    bit<16> unused2;
}

header udp_t{
    port_t src_port;
    port_t dst_port;
    bit<16> unused;
    bit<16> checksum;
}

struct headers {
    ethernet_t          ethernet;
    nat_metadata_t      metadata;
    ipv4_t              ipv4;
    tcp_t               tcp;
    udp_t               udp;
}

struct map_entry_t {// size == 16
    ipv4_flow_id_t  id;
    port_t          eport;
}

enum bit<2> hdr_type_t {
    normal = 1,
    with_meta = 2,
    meta_only = 3
}

struct metadata {
    /* parser -> ingress */
    bool            is_tcp;

    bool            metadata_checksum_correct;
    bool            ipv4_checksum_correct;
    bit<16>         L4_neg_partial_checksum;
    

    /* ingress.get_transition_type -> ingress */
    bit<3>          transition_type;    // 0:in->out/nfv, 1:out->in/nfv, 2:nfv->out, 3:nfv->in, 4:nfv_update 
    index_t         reverse_index;  
    bool            reverse_eport_valid;
    bool            control_ignore0;
    bool            control_ignore1;
    bool            control_ignore2;
    bool            control_ignore3;

    /* ingress */
    bool            ingress_end;
    bit<2>          way_out;            // 0:drop, 1:to an out port, 2:to nfv

    // packet info
    ipv4_flow_id_t  id;          
    index_t         index;
    time_t          time;
    // register
    map_entry_t     reg_map;
    bit<32>         reg_tmp3;
    bit<32>         reg_tmp2;
    bit<32>         reg_tmp1;
    bit<32>         reg_tmp0;

    bool            timeout;
    bool            match;
    version_t       version_diff;
    version_t       version;
    

    /* ingress -> deparser */
    bool            update_metadata;
    bool            update_ip;
    bool            update_tcp;
    bool            update_udp;

    /* ingress checksum -> egress checksum */
    bool            tmp_bool1;
    bool            tmp_bool2;
    bool            tmp_bool3;
    bool            tmp_bool4;

}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserI(packet_in packet,
               out headers hdr,
               out metadata meta,
               out ingress_intrinsic_metadata_t ig_intr_md) {

    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) metadata_csum;
    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_csum;
    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) L4_csum;

    state start {
        packet.extract(ig_intr_md);
        transition parse_port_metadata;
    }


    state parse_port_metadata {
        //packet.extract(ig_md.port_md);
        //packet.extract(meta);
        packet.advance(64);
#if __TARGET_TOFINO__ == 2
	// We need to advance another 128 bits since t2na metadata
    	// is of 192 bits in total and my_port_metadata_t only 
	// consumes 64 bits
        packet.advance(128);
#endif
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(ig_intr_md.ingress_port ++ hdr.ethernet.ether_type) {//没检查MAC addr，没必要
            NFV_PORT ++ TYPE_METADATA                   :   parse_metadata;
            NFV_PORT ++ TYPE_IPV4                       :   reject;
            (9w0 ++ TYPE_IPV4) &&& (9w0 ++ 16w0xffff)   :   parse_ipv4_with_transition_type;
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata);
        metadata_csum.add(hdr.metadata);
        meta.metadata_checksum_correct = metadata_csum.verify();
        transition select(hdr.metadata.type) {
            8w0b010_00000 :   mark_type_2;
            8w0b100_00000 :   mark_type_3;
            8w0b001_00000 :   mark_type_4;
        }
    }

    state mark_type_2 {
        meta.transition_type = 2;
        transition parse_inner_ipv4;
    }

    state mark_type_3 {
        meta.transition_type = 3;
        transition parse_inner_ipv4;
    }

    state mark_type_4 {
        meta.transition_type = 4;
        transition accept;
    }

    state parse_ipv4_with_transition_type {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        transition select(ip.src_addr) {
            LAN_ADDR &&& LAN_ADDR_MASK  :   parse_sin;
            default                     :   parse_sout;
        }
    }

    state parse_sin {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        transition select(ip.dst_addr) {
            LAN_ADDR &&& LAN_ADDR_MASK  :   reject;
            default                     :   mark_type_0;
        }
    }

    state parse_sout {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        transition select(ip.dst_addr) {
            NAT_ADDR    :   mark_type_1;
            default     :   reject;
        }
    }

    state mark_type_0 {
        meta.transition_type = 0;
        transition parse_inner_ipv4;
    }

    state mark_type_1 {
        meta.transition_type = 1;
        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.ipv4);
        ipv4_csum.add(hdr.ipv4);
        meta.ipv4_checksum_correct = ipv4_csum.verify();
        L4_csum.subtract({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
        // fill id
        meta.id.src_addr = hdr.ipv4.src_addr;
        meta.id.dst_addr = hdr.ipv4.dst_addr;
        meta.id.protocol = hdr.ipv4.protocol;
        meta.id.zero = 0;

        transition select(hdr.ipv4.protocol ++ hdr.ipv4.ihl) {
            TCP_PROTOCOL ++ 4w5: parse_tcp;
            UDP_PROTOCOL ++ 4w5: parse_udp;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        L4_csum.subtract({hdr.tcp.src_port, hdr.tcp.dst_port});
        meta.L4_neg_partial_checksum = L4_csum.get();
        meta.is_tcp = true;

        // fill id
        meta.id.src_port = hdr.tcp.src_port;
        meta.id.dst_port = hdr.tcp.dst_port;

        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        L4_csum.subtract({hdr.udp.src_port, hdr.udp.dst_port});
        meta.L4_neg_partial_checksum = L4_csum.get();
        meta.is_tcp = false;

        // fill id
        meta.id.src_port = hdr.udp.src_port;
        meta.id.dst_port = hdr.udp.dst_port;

        transition accept;
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control get_transition_type(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md) {

    Register<bit<16>, bit<16>>(1) help;

    RegisterAction<bit<16>, bit<16>, bit>(help) reg_check_tcp_eport = {
        void apply(inout bit<16> reg, out bit ret) {
            if(PORT_MIN < hdr.tcp.dst_port && (bit<32>)hdr.tcp.dst_port < PORT_MAX)
                ret = 1;
            else 
                ret = 0;
        }
    };
    RegisterAction<bit<16>, bit<16>, bit>(help) reg_check_udp_eport = {
        void apply(inout bit<16> reg, out bit ret) {
            if(PORT_MIN < hdr.udp.dst_port && (bit<32>)hdr.udp.dst_port < PORT_MAX)
                ret = 1;
            else 
                ret = 0;
        }
    };

    action check_tcp_eport() {
        meta.reverse_eport_valid = (bool)reg_check_tcp_eport.execute(0);
    }

    action check_udp_eport() {
        meta.reverse_eport_valid = (bool)reg_check_udp_eport.execute(0);
    }

    apply {
        //if(ig_intr_md.ingress_port == NFV_PORT) {

            //我不想检查MAC地址，MAC地址无所谓了
            
            //ethertype不需要检查，parser筛选过了

            /*if(hdr.metadata.zero1 != 0 || hdr.metadata.zero2 != 0) {
                meta.control_ignore = true;
            }*/
            /*
            bit<5> update_valid_bits = (bit<2>)meta.hdr_type ++ hdr.metadata.is_to_in ++ hdr.metadata.is_to_out ++ hdr.metadata.is_update;
            bit<2> type_meta_only = (bit<2>)hdr_type_t.meta_only;
            bit<2> type_with_meta = (bit<2>)hdr_type_t.with_meta;
            
            if(update_valid_bits == type_with_meta ++ 3w0b010) {
                meta.transition_type = 2;
                meta.control_ignore1 = false;
            }
            else if(update_valid_bits == type_with_meta ++ 3w0b100) {
                meta.transition_type = 3;
                meta.control_ignore1 = false;
            }
            else if(update_valid_bits == type_meta_only ++ 3w0b001) {
                meta.transition_type = 4;
                meta.control_ignore1 = false;
            } 
            else {
                meta.control_ignore1 = true;
            }
            */
        /*}
        else {*/
            /*
            if(meta.hdr_type != hdr_type_t.normal) 
                meta.control_ignore2 = true;
            else 
                meta.control_ignore2 = false;
            */

            // TODO 改这个else，或许可以直接用一个table来记录哪个是LAN port
            // 那个是WAN port，这样比较省事

            // 用register action 比较 dst_port 和 PORT_MIN/PORT_MAX，获取reverse_index和reverse_eport_valid
            /*
            if(meta.is_tcp) {
                check_tcp_eport();
                meta.reverse_index = hdr.tcp.dst_port - PORT_MIN;
            }
            else {
                check_udp_eport();
                meta.reverse_index = hdr.udp.dst_port - PORT_MIN;
            }
            */

            //不知道为什么，control里用< <= > >=会出问题
            // src IN LAN
            /*
            if((hdr.ipv4.src_addr & LAN_ADDR_MASK) == LAN_ADDR)
                meta.tmp_bool1 = true;
            else 
                meta.tmp_bool1 = false;
            
            // dst OUT LAN
            if((hdr.ipv4.dst_addr & LAN_ADDR_MASK) == LAN_ADDR) 
                meta.tmp_bool2 = false;
            else 
                meta.tmp_bool2 = true;
            */
        //}
        /*
        if(ig_intr_md.ingress_port != NFV_PORT) {
            
            if(meta.tmp_bool1 && meta.tmp_bool2) {
                hdr.metadata.is_to_in = 0;
                hdr.metadata.is_to_out = 1;
                meta.transition_type = 0;
                meta.control_ignore3 = false;
            }
            else if(!meta.tmp_bool1 && hdr.ipv4.dst_addr == NAT_ADDR && meta.reverse_eport_valid) {
                hdr.metadata.is_to_in = 1;
                hdr.metadata.is_to_out = 0;
                meta.transition_type = 1;
                meta.control_ignore3 = false;
            }
            else {
                meta.control_ignore3 = true;
            }
            
        }*/
        if(meta.transition_type == 1) {
            if(meta.is_tcp) {
                check_tcp_eport();
                meta.reverse_index = hdr.tcp.dst_port - PORT_MIN;
            }
            else {
                check_udp_eport();
                meta.reverse_index = hdr.udp.dst_port - PORT_MIN;
            }
        }
    }
}

control get_id(
        in headers hdr,
        inout metadata meta)
{
    apply {
        if(meta.is_tcp) {
            meta.id.src_port = hdr.tcp.src_port;
            meta.id.dst_port = hdr.tcp.dst_port;
        }
        else {
            meta.id.src_port = hdr.udp.src_port;
            meta.id.dst_port = hdr.udp.dst_port;
        }
        meta.id.src_addr = hdr.ipv4.src_addr;
        meta.id.dst_addr = hdr.ipv4.dst_addr;
        meta.id.protocol = hdr.ipv4.protocol;
        meta.id.zero = 0;
    }
}

control send_out(
        inout headers hdr,
        inout metadata meta,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md, 
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md
        ) {

    action drop() {
        ig_intr_dprs_md.drop_ctl = 0x1;
    }

    action ipv4_forward(bit<9> port, mac_addr_t dmac) {
        ig_intr_tm_md.ucast_egress_port = port;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ip2port_dmac{
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 16;
        default_action = drop();
    }

    apply {
        if(meta.way_out == 1) {// to an out port
            ip2port_dmac.apply();
            //port2smac.apply();
        }
        else if(meta.way_out == 2) {// to nfv
            hdr.ethernet.ether_type = TYPE_METADATA;
            hdr.ethernet.src_addr = 48w1;
            hdr.ethernet.dst_addr = 48w2;
            hdr.metadata.setValid();
        }
        else {
            drop();
        }
        
        if(meta.way_out == 2) {
            
            hdr.metadata.src_addr = meta.id.src_addr;
            hdr.metadata.dst_addr = meta.id.dst_addr;
            hdr.metadata.src_port = meta.id.src_port;
            hdr.metadata.dst_port = meta.id.dst_port;
            hdr.metadata.protocol = meta.id.protocol;
            hdr.metadata.zero1 = 0;
        
            //hdr.metadata.switch_port = switch_port;
            
            //hdr.metadata.is_to_in
            //hdr.metadata.is_to_out
            
            //hdr.metadata.is_update = timeout;
            
            //hdr.metadata.version = version;
            //hdr.metadata.index = index;
            hdr.metadata.nfv_time = 0;
            hdr.metadata.checksum = 0;
            
            ig_intr_tm_md.ucast_egress_port = NFV_PORT;
        }
        //@pragma stage
        
        if(meta.way_out == 2) {
            if(meta.transition_type == 0) {
                hdr.metadata.switch_port = meta.reg_map.eport;

                //hdr.metadata.is_to_in = 0;
                //hdr.metadata.is_to_out = 1;
                //hdr.metadata.is_update = (bit)meta.timeout;
                //hdr.metadata.zero2 = 0;
                //hdr.metadata.type = 2w0b01 ++ (bit)meta.timeout ++ 5w0;//8w0b010_00000 | (8w1<< );

                hdr.metadata.version = meta.version;
                hdr.metadata.index = meta.index;
            }
            else {
                hdr.metadata.switch_port = 0;

                //hdr.metadata.type = 8w0b100_00000;

                hdr.metadata.version = 0;
                hdr.metadata.index = 0;
            }
        }
        
    }
    //学长，能帮我看看这个PHV分配的问题吗，出问题的是一段连续的赋值代码，
}

control IngressP(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    

    Hash<index_t>(HashAlgorithm_t.CRC16) hashmap;
    
    Register<bit<32>, index_t>((bit<32>)SWITCH_PORT_NUM, 0) map3;
    Register<bit<32>, index_t>((bit<32>)SWITCH_PORT_NUM, 0) map2;
    Register<bit<32>, index_t>((bit<32>)SWITCH_PORT_NUM, 0) map1;
    Register<bit<32>, index_t>((bit<32>)SWITCH_PORT_NUM, 0) map0;
    // TODO：time后续可以改成8bit
    Register<time_t, index_t>((bit<32>)SWITCH_PORT_NUM, FOREVER_TIMEOUT) primary_time;
    Register<version_t, index_t>((bit<32>)SWITCH_PORT_NUM, 0) version;
    Register<index_t, index_t>(PORT_MAX - (bit<32>)PORT_MIN, 0) reverse_map;

    RegisterAction<bit<32>, index_t, bit<32>>(map3) reg_map3_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(map2) reg_map2_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(map1) reg_map1_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(map0) reg_map0_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(map3) reg_map3_swap = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
            reg = meta.reg_tmp3;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(map2) reg_map2_swap = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
            reg = meta.reg_tmp2;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(map1) reg_map1_swap = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
            reg = meta.reg_tmp1;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(map0) reg_map0_swap = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
            reg = meta.reg_tmp0;
        }
    };

    RegisterAction<time_t, index_t, bool>(primary_time) reg_update_time_on_match = {
        void apply(inout time_t reg_time, out bool ret) {
            // "meta.time - FOREVER_TIMEOUT > AGING_TIME_US" is always true
            if(meta.time - reg_time > AGING_TIME_US) {
                reg_time = FOREVER_TIMEOUT;
                ret = true;
            }
            else {
                reg_time = meta.time;
                ret = false;
            }
        }
    };

    RegisterAction<time_t, index_t, bool>(primary_time) reg_update_time_on_mismatch = {
        void apply(inout time_t reg_time, out bool ret) {
            if(meta.time - reg_time > AGING_TIME_US) {
                reg_time = FOREVER_TIMEOUT;
                ret = true;
            }
            else {
                ret = false;
            }
        }
    };

    RegisterAction<time_t, index_t, void>(primary_time) reg_write_time = {
        void apply(inout time_t reg_time) {
            reg_time = meta.time;
        }
    };

    RegisterAction<version_t, index_t, version_t>(version) reg_read_version = {
        void apply(inout version_t reg_version, out version_t ret) {
            ret = reg_version;
        }
    };

    RegisterAction<version_t, index_t, version_t>(version) reg_update_version = {
        void apply(inout version_t reg_version, out version_t ret) {
            ret = meta.version - reg_version;
            if(meta.version - reg_version == 1) {
                reg_version = meta.version;
            }
        }
    };

    RegisterAction<index_t, index_t, index_t>(reverse_map) reg_reverse_map_read = {
        void apply(inout index_t reg_index, out index_t ret) {
            ret = reg_index;
        }
    };

    RegisterAction<index_t, index_t, void>(reverse_map) reg_reverse_map_write = {
        void apply(inout index_t reg_index) {
            reg_index = meta.index;
        }
    };

    RegisterAction<index_t, index_t, void>(reverse_map) reg_reverse_map_clear = {
        void apply(inout index_t reg_index) {
            reg_index = 0;
        }
    };

    action map3_read(in index_t index) {
        meta.reg_map.id.src_addr = reg_map3_read.execute(index);
    }

    action map2_read(in index_t index) {
        meta.reg_map.id.dst_addr = reg_map2_read.execute(index);
    }

    action map1_read(in index_t index) {
        bit<32>tmp = reg_map1_read.execute(index);
        meta.reg_map.id.src_port = tmp[31:16];
        meta.reg_map.id.dst_port = tmp[15:0];
    }

    action map0_read(in index_t index) {
        bit<32>tmp = reg_map0_read.execute(index);
        meta.reg_map.id.protocol = tmp[31:24];
        meta.reg_map.id.zero = tmp[23:16];
        meta.reg_map.eport = tmp[15:0];
    }

    action map_swap(in index_t index) {
        meta.reg_tmp3 = meta.reg_map.id.src_addr;
        meta.reg_tmp2 = meta.reg_map.id.dst_addr;
        meta.reg_tmp1 = meta.reg_map.id.src_port ++ meta.reg_map.id.dst_port;
        meta.reg_tmp0 = meta.reg_map.id.protocol ++ meta.reg_map.id.zero ++ meta.reg_map.eport;

        meta.reg_tmp3 = reg_map3_swap.execute(index);
        meta.reg_tmp2 = reg_map2_swap.execute(index);
        meta.reg_tmp1 = reg_map1_swap.execute(index);
        meta.reg_tmp0 = reg_map0_swap.execute(index);
        meta.reg_map = {
            {meta.reg_tmp3,
            meta.reg_tmp2,
            meta.reg_tmp1[31:16],
            meta.reg_tmp1[15:0],
            meta.reg_tmp0[31:24],
            meta.reg_tmp0[23:16]},
            meta.reg_tmp0[15:0]
        };
    }

    action update_time_on_match(in index_t index) {
        meta.timeout = reg_update_time_on_match.execute(index);
    }

    action update_time_on_mismatch(in index_t index) {
        meta.timeout = reg_update_time_on_mismatch.execute(index);
    }

    action write_time(in index_t index) {
        reg_write_time.execute(index);
    }

    action read_version(in index_t index) {
        meta.version = reg_read_version.execute(index);
    }

    action update_version(in index_t index) {
        meta.version_diff = reg_update_version.execute(index);
    }

    action reverse_map_read(in index_t index) {
        meta.index = reg_reverse_map_read.execute(index);
        //ret 
    }

    action reverse_map_write(in index_t index) {
        reg_reverse_map_write.execute(index);
    }

    action reverse_map_clear(in index_t index) {
        reg_reverse_map_clear.execute(index);
    }

    action get_index() {
        ipv4_flow_id_t id = meta.id;
        meta.index = hashmap.get({id.src_addr, id.dst_addr, id.src_port, id.dst_port, id.protocol, id.zero}, 
                                (index_t)0, (index_t)SWITCH_PORT_NUM);
        //ret
        // port PORT_MIN and index 0 is reserved
    }

    action get_time() {
        meta.time = 1w0 ++ (bit<31>)ig_intr_md.ingress_mac_tstamp;
        // 48->31->32
    }    

    action get_smac(mac_addr_t smac) {
        hdr.ethernet.src_addr = smac;
    }

    table port2smac{
        key = {
            ig_intr_tm_md.ucast_egress_port: exact;
        }
        actions = {
            get_smac;
        }
        size = 16;
    }

    apply {
        // bypass_egress
        ig_intr_tm_md.bypass_egress = true;

        // 检查parse和checksum
        if(ig_intr_prsr_md.parser_err != 0 ||                               // parse error
            (hdr.metadata.isValid() && !meta.metadata_checksum_correct) ||  // metadata checksum error
            (hdr.ipv4.isValid() && !meta.ipv4_checksum_correct)) {          // ipv4 checksum error
            meta.way_out = 0;
            meta.ingress_end = true;
        }
        else {
            // 检查反向流的eport合法性
            get_transition_type.apply(hdr, meta, ig_intr_md);//这玩意儿4/5个stage
            meta.ingress_end = false;// 这是唯一一个false，用于初始化
        }

        // 检查反向流的eport合法性
        if(meta.ingress_end == false && !meta.reverse_eport_valid) {
            meta.way_out = 0;
            meta.ingress_end = true;
        }
        
        // 初始化
        // time
        get_time();

        if(meta.ingress_end == false) {
            if (meta.transition_type == 0) {
                get_index();//这个action会引起compiler bug???
            }
            else if (meta.transition_type == 1) {
                reverse_map_read(meta.reverse_index);// 这个始终会报错？？？？？？？？？？？？？？？？？？？？？？？
                // 注意！！这里读出来的meta.index可能为0
                //assert(meta.index < SWITCH_PORT_NUM); //
            }
            else if (meta.transition_type == 2 || meta.transition_type == 3) {
                hdr.metadata.setInvalid();
                hdr.ethernet.ether_type = TYPE_IPV4;
                meta.way_out = 1;
                meta.ingress_end = true;
            }
        }

        //if(meta.ingress_end == false) {
            
        //}

        // register map
        if(meta.ingress_end == false) {
            if (meta.transition_type == 0 || meta.transition_type == 1) {
                map3_read(meta.index);
                map2_read(meta.index);
                map1_read(meta.index);
                map0_read(meta.index);
            }
        }
        
        // version
        if(meta.ingress_end == false) {
            if (meta.transition_type == 0 || meta.transition_type == 1) {
                read_version(meta.index);
            }
        }

        
        // this is for reverse match
        
        
        if(meta.ingress_end == false) {
            if (meta.transition_type == 0) {

                if(meta.reg_map.id.src_addr == meta.id.src_addr) 
                    meta.tmp_bool1 = true;
                else   
                    meta.tmp_bool1 = false;

                if(meta.reg_map.id.dst_addr == meta.id.dst_addr)
                    meta.tmp_bool2 = true;
                else   
                    meta.tmp_bool2 = false;
                
                if(meta.reg_map.id.src_port == meta.id.src_port)
                    meta.tmp_bool3 = true;
                else   
                    meta.tmp_bool3 = false;
                
                if(meta.reg_map.id.dst_port == meta.id.dst_port && meta.reg_map.id.protocol == meta.id.protocol)
                    meta.tmp_bool4 = true;
                else   
                    meta.tmp_bool4 = false;
                
            }
        
            //根据实验，下面这个分支不能与上面那个同时存在，分成两个表(else if -> if)并不能解决问题
            //初步分析，两个同时存在时，其依赖的上游的某个stage中的分支也必须同时存在，从而导致上游某个stage中的两个分支产生了冲突
            else if (meta.transition_type == 1) {
                if(meta.reg_map.id.dst_addr == meta.id.src_addr)
                    meta.tmp_bool1 = true;
                else   
                    meta.tmp_bool1 = false;

                if(meta.reg_map.id.dst_port == meta.id.src_port && meta.reg_map.id.protocol == meta.id.protocol) 
                    meta.tmp_bool2 = true;
                else 
                    meta.tmp_bool2 = false;

                if(meta.reg_map.eport == meta.id.dst_port)
                    meta.tmp_bool3 = true;
                else 
                    meta.tmp_bool3 = false;
            }
        }   
            
        // register time
        
        if(meta.ingress_end == false) {
            if (meta.transition_type == 0) {
                if(meta.tmp_bool1 && meta.tmp_bool2 && meta.tmp_bool3 && meta.tmp_bool4) {
                    meta.match = true;
                    update_time_on_match(meta.index);
                }
                else {
                    meta.match = false;
                    update_time_on_mismatch(meta.index);
                }
            }
            else if (meta.transition_type == 1) {
                if(!meta.tmp_bool3) {
                    // eport is not keep by switch
                    meta.way_out = 2;
                    meta.ingress_end = true;
                }
                else if(meta.tmp_bool1 && meta.tmp_bool2) {
                    update_time_on_match(meta.index);
                    // it is not necessary to update_time_on_mismatch
                }
                else {
                    // eport is keep by switch but id mismatch
                    meta.way_out = 0;
                    meta.ingress_end = true;
                }    
            }
        }
        
        if(meta.ingress_end == false) {
            if (meta.transition_type == 0) {
                if(meta.match && meta.timeout == false) {
                    // translate
                    
                    hdr.ipv4.src_addr = NAT_ADDR;
                    if(meta.is_tcp) 
                        hdr.tcp.src_port = meta.reg_map.eport;
                    else
                        hdr.udp.src_port = meta.reg_map.eport;

                    meta.way_out = 1;
                    meta.ingress_end = true;
                }
                else {
                    //为什么加这个就会出现未分配？？？？？？？？？？？？？？？？？？？？？？
                    meta.way_out = 2;
                    meta.ingress_end = true;
                }
            }
            else if (meta.transition_type == 1) {
                if(!meta.timeout) {
                    // reverse_translate
                    hdr.ipv4.dst_addr = meta.reg_map.id.src_addr;
                    if(meta.is_tcp)
                        hdr.tcp.dst_port = meta.reg_map.id.src_port;
                    else
                        hdr.udp.dst_port = meta.reg_map.id.src_port;

                    meta.way_out = 1;
                    meta.ingress_end = true;
                }
                else {
                    // aging
                    meta.way_out = 0;
                    meta.ingress_end = true;
                }  
            }
        }

        send_out.apply(hdr, meta, ig_intr_dprs_md, ig_intr_tm_md);
    
        
        
        
            

        /*
        else if(meta.transition_type == 0) {
            
            get_index();
            
            map3_read(meta.index);
            map2_read(meta.index);
            map1_read(meta.index);
            map0_read(meta.index);
            
            meta.match = meta.reg_map.id == meta.id;
            if(meta.match) {
                update_time_on_match(meta.index);
            }
            else {
                update_time_on_mismatch(meta.index);
            }
            if(meta.match && !meta.timeout) {
                translate();
                meta.apply_dst = true;
                //ip2port_dmac.apply();
                //return;
            }
            else {
                read_version(meta.index);
                set_metadata(true);
                send_to_NFV();
            }        
        }
        else if(meta.transition_type == 3) {
            meta.apply_dst = true;
            //ip2port_dmac.apply();
        }
        else if(meta.transition_type == 2) {
            meta.apply_dst = true;
            //ip2port_dmac.apply();
        }
        else if(meta.transition_type == 4) {
            meta.index = hdr.metadata.index;
            meta.version = hdr.metadata.version;
            update_version(meta.index);
    
            //if meta.entry.map == hdr.metadata.secondary_map return a redundent ACK
            if(meta.version_diff > 1) {
                drop();
                return;
            }
            if(meta.version_diff == 1) {
                meta.reg_map = {
                    {hdr.metadata.src_addr,
                    hdr.metadata.dst_addr,
                    hdr.metadata.src_port,
                    hdr.metadata.dst_port, 
                    hdr.metadata.protocol,
                    0},
                    hdr.metadata.switch_port
                };
                reverse_map_write(meta.reg_map.eport - PORT_MIN);
                map_swap(meta.index);
                write_time(meta.index);

                //为了时序上是先reverse_map后map，我觉得最好不要写下面这行
                //reverse_map_clear(meta.reg_map.eport - PORT_MIN);
            }

            send_to_NFV();
        }
        
        
        meta.update_metadata = hdr.metadata.isValid();
        meta.update_ip = hdr.ipv4.isValid();
        meta.update_tcp = hdr.tcp.isValid();
        meta.update_udp = hdr.udp.isValid() && (hdr.udp.checksum != 0);

        if(ig_intr_tm_md.ucast_egress_port != NFV_PORT) {
            hdr.metadata.setInvalid();
            hdr.ethernet.ether_type = TYPE_IPV4;
            port2smac.apply();
        }
        */
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyComputeChecksum(inout headers hdr, in metadata meta) {

    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) csum16;

    apply {
        /*
        if(meta.update_metadata) {
            hdr.metadata.checksum = csum16.update(
                {hdr.metadata.src_addr, 
                hdr.metadata.dst_addr, 
                hdr.metadata.src_port, 
                hdr.metadata.dst_port, 
                hdr.metadata.protocol,
                hdr.metadata.zero1,

                hdr.metadata.switch_port,

                hdr.metadata.version,

                hdr.metadata.is_to_in,
                hdr.metadata.is_to_out,
                hdr.metadata.is_update,
                hdr.metadata.zero2,

                hdr.metadata.index,
                hdr.metadata.nfv_time}
            );
        }
        
        if(meta.update_ip) {
            hdr.ipv4.checksum = csum16.update(
                {hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.unused1,
                hdr.ipv4.total_length,
                hdr.ipv4.unused2,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr}
            );
        }
        bit<32> checksum;
        
        if(meta.update_tcp) {
            checksum = (bit<32>)csum16.update(
                {hdr.ipv4.src_addr, 
                hdr.ipv4.dst_addr,
                8w0,
                hdr.ipv4.protocol,
                meta.L4_length,

                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.unused1,
                hdr.tcp.unused2}
            );
            checksum = (bit<32>)hdr.tcp.checksum + (checksum + (bit<32>)(0xffff^meta.L4_checksum_partial));
            checksum = (checksum & 0xffff) + (checksum >> 16);
            checksum = (checksum & 0xffff) + (checksum >> 16);
            if(checksum == 0) checksum = 0xffff;
            hdr.tcp.checksum = (bit<16>)checksum;
        }
        
        if(meta.update_udp) {
            checksum = (bit<32>)csum16.update(
                {hdr.ipv4.src_addr, 
                hdr.ipv4.dst_addr,
                8w0,
                hdr.ipv4.protocol,
                meta.L4_length,

                hdr.udp.src_port,
                hdr.udp.dst_port,
                hdr.udp.unused}
            );
            checksum = (bit<32>)hdr.udp.checksum + (checksum + (bit<32>)(0xffff^meta.L4_checksum_partial));
            checksum = (checksum & 0xffff) + (checksum >> 16);
            checksum = (checksum & 0xffff) + (checksum >> 16);
            if(checksum == 0) checksum = 0xffff;
            hdr.udp.checksum = (bit<16>)checksum;
        }
        */
    }
}

control DeparserI(
        packet_out packet,
        inout headers hdr,
        in metadata meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    apply{
        MyComputeChecksum.apply(hdr, meta);

        packet.emit(hdr.ethernet);
        packet.emit(hdr.metadata);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

parser ParserE(packet_in b,
               out headers hdr,
               out metadata meta,
               out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}

control EgressP(
        inout headers hdr,
        inout metadata meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply { }
}

control DeparserE(packet_out b,
                  inout headers hdr,
                  in metadata meta,
                  in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply { }
}

Pipeline(ParserI(), IngressP(), DeparserI(), ParserE(), EgressP(), DeparserE()) pipe;

Switch(pipe) main;
