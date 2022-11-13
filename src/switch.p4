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
typedef bit<32> flow_num_t;
typedef bit<16> port_t;
typedef bit<16> time_t;
typedef bit<8> version_t;
typedef bit<16> checksum_t;
typedef bit<SHARED_SWITCH_REG_NUM_LOG> index_hi_t;

const bit<8>  TCP_PROTOCOL = 0x06;
const bit<8>  UDP_PROTOCOL = 0x11;

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_METADATA = SHARED_TYPE_METADATA;

//you can change these by tables to support dynamic & multiple LAN address allocation
const ip4_addr_t LAN_ADDR = SHARED_LAN_ADDR;// 192.168.0.0
const ip4_addr_t LAN_ADDR_MASK = SHARED_LAN_ADDR_MASK;// /24

const flow_num_t SWITCH_FLOW_NUM = SHARED_SWITCH_FLOW_NUM;
const flow_num_t SWITCH_FLOW_NUM_PER_REG = SHARED_SWITCH_FLOW_NUM_PER_REG;

const time_t AGING_TIME = SHARED_AGING_TIME_FOR_SWITCH;
const time_t HALF_AGING_TIME = SHARED_AGING_TIME_FOR_SWITCH / 2;

const mac_addr_t SWITCH_INNER_MAC = (bit<16>)SHARED_SWITCH_INNER_MAC_HI16 ++ (bit<32>)SHARED_SWITCH_INNER_MAC_LO32;
const mac_addr_t NF_INNER_MAC = (bit<16>)SHARED_NF_INNER_MAC_HI16 ++ (bit<32>)SHARED_NF_INNER_MAC_LO32;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>   ether_type;
}

header nat_metadata_t {//26
    ip4_addr_t  src_addr;
    ip4_addr_t  dst_addr;
    port_t      src_port;
    port_t      dst_port;
    bit<8>      protocol;
    bit<8>      zero;

    ip4_addr_t  wan_addr;
    port_t      wan_port;
    version_t   version;

    bit<8>      type_and_update;
    // 3 meanings:
    // when type == 0/1, "update" is a hint for server 
    // when type == 6 and the packet is from server, it means if the packet is a force update
    // when type == 6 and the packet is to server, it means if switch accept the update

    checksum_t  checksum;

    flow_num_t  index; // index is the hash value of flow id
    time_t      switch_time;// 因为一个ACK返回的时候wait_entry可能已经没了，所以时间需要记录在packet里
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    unused1;
    bit<16>   total_length;
    bit<32>   unused2;
    bit<8>    ttl;
    bit<8>    protocol;
    checksum_t   checksum;
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
    checksum_t checksum;
    bit<16> unused2;
}

header udp_t{
    port_t src_port;
    port_t dst_port;
    bit<16> unused;
    checksum_t checksum;
}

header L3L4_t {
    bit<72> unused1;
    bit<8> protocol;
    bit<16> unused2;
    ip4_addr_t src_addr;
    ip4_addr_t dst_addr;
    port_t src_port;
    port_t dst_port;
}

struct headers {
    ethernet_t          ethernet;
    nat_metadata_t      metadata;
    ipv4_t              ipv4;
    tcp_t               tcp;
    udp_t               udp;
}

struct nf_port_t{
    bit<2>  port_type; 
    bit<14>  unused;
}

struct ingress_metadata {
    /* parser -> ingress */
    bool            metadata_checksum_err;
    //checksum_t      L4_partial_complement_sum;
    nf_port_t       nf_port_hdr;
    time_t          time;
    bit<4>          transition_type;    // 0:in->out/nf, 1:out->in/nf, 2:nf->out, 3:nf->in, 4:in->nf, 5:out->nf, 6:update, 7:drop

    /* ingress */
    bool            ingress_end;
    bit<1>          update_timeout;
    bit<1>          all_flow_timeout;
    bit<1>          main_flow_timeout;       
    time_t          delta_time;
    bit<1>          accept;

    index_hi_t      index_hi;
    flow_num_t      index_lo;

    ipv4_flow_id_t  id;
    ipv4_flow_id_t  cmp;
    
    bit<1>          match;
    bit<1>          need_match;

    version_t       version_diff;
}

struct egress_metadata {
    checksum_t      L4_partial_complement_sum;
    bool            is_tcp;
    bool            update_udp_checksum;
    bit<4>          transition_type;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser IngressParser(packet_in packet,
               out headers hdr,
               out ingress_metadata meta,
               out ingress_intrinsic_metadata_t ig_intr_md) {

    /*
    关于校验和，我这样处理：
        metadata checksum：检验并更新
        ip checksum：不检验，只更新（因为很多情况下没人在乎ip checksum）
        tcp/udp checksum：只增量更新（udp为0不更新）
    */
    Checksum() metadata_csum;

    state start {
        packet.extract(ig_intr_md);

        meta.time = ig_intr_md.ingress_mac_tstamp[39:24];// truncate
        // meta.time *= 2^16/1000
        
        transition select(ig_intr_md.resubmit_flag) {
            0 : parse_port_metadata;
        }
    }

    state parse_port_metadata {
        meta.nf_port_hdr = port_metadata_unpack<nf_port_t>(packet);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.ether_type ++ meta.nf_port_hdr.port_type) {//没检查MAC addr，没必要
            TYPE_METADATA ++ 2w2:   parse_metadata;
            TYPE_IPV4 ++ 2w0:   parse_ipv4_from_LAN;
            TYPE_IPV4 ++ 2w1:   maybe_type_1;
            default         :   parse_other_flow;
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata);
        metadata_csum.add(hdr.metadata);
        meta.metadata_checksum_err = metadata_csum.verify();
        transition select(hdr.metadata.type_and_update) {
            (4w2 ++ 4w0) &&& (4w15 ++ 4w0):   mark_type_2;
            (4w3 ++ 4w0) &&& (4w15 ++ 4w0):   mark_type_3;
            (4w6 ++ 4w0) &&& (4w15 ++ 4w0):   mark_type_6;
        }
    }

    state mark_type_2 {
        meta.transition_type = 2;
        transition accept;
    }

    state mark_type_3 {
        meta.transition_type = 3;
        transition accept;
    }

    state mark_type_6 {
        meta.transition_type = 6;
        transition accept;
    }

    state parse_ipv4_from_LAN {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        transition select(ip.dst_addr) {
            LAN_ADDR &&& LAN_ADDR_MASK  :   parse_other_flow;// in->in
            default                     :   maybe_type_0;// in->out
        }
    }

    state maybe_type_0 {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        transition select(ip.protocol ++ ip.ihl) {
            TCP_PROTOCOL ++ 4w5 :   mark_type_0;
            UDP_PROTOCOL ++ 4w5 :   mark_type_0;
            default             :   parse_other_flow;
        }
    }

    state mark_type_0 {
        meta.transition_type = 0;
        transition initialize_metadata;
    }

    state maybe_type_1 {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        transition select(ip.protocol ++ ip.ihl) {
            TCP_PROTOCOL ++ 4w5 :   mark_type_1;
            UDP_PROTOCOL ++ 4w5 :   mark_type_1;
            default             :   parse_other_flow;
        }
    }

    state mark_type_1 {
        meta.transition_type = 1;
        transition initialize_metadata;
    }

    state initialize_metadata{
        /*
        hdr.metadata.setValid();
        meta.metadata_checksum_err = false;

        hdr.metadata.index = 0;//这个是为了在pipe内赋hash值时只赋值一部分
        
        L3L4_t l3l4 = packet.lookahead<L3L4_t>();//这是为了“原地更新”
        hdr.metadata.src_addr = l3l4.src_addr;
        hdr.metadata.dst_addr = l3l4.dst_addr;
        hdr.metadata.src_port = l3l4.src_port;
        hdr.metadata.dst_port = l3l4.dst_port;
        hdr.metadata.protocol = l3l4.protocol;
        hdr.metadata.zero = 0;

        hdr.metadata.switch_time = meta.time;

        meta.id.src_addr = l3l4.src_addr;
        meta.id.dst_addr = l3l4.dst_addr;
        meta.id.src_port = l3l4.src_port;
        meta.id.dst_port = l3l4.dst_port;
        meta.id.protocol = l3l4.protocol;
        meta.id.zero = 0;
        */
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);   
        transition accept;
    }

    state parse_other_flow {
        meta.metadata_checksum_err = false;
        meta.transition_type = 8;
        transition accept;
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control send_out(
        inout headers hdr,
        inout ingress_metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md, 
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md
        ) {

    action drop() {
        ig_intr_dprs_md.drop_ctl = 0x1;
    }

    action set_egress_port(in bit<9> port) {
        ig_intr_dprs_md.drop_ctl = 0;//这个drop_ctl=0一定不能省略，不知道为什么，明明文档说初始化为0的
        ig_intr_tm_md.ucast_egress_port = port;
    }

    action l3_forward(bit<9> port, mac_addr_t smac, mac_addr_t dmac) {
        set_egress_port(port);
        hdr.ethernet.src_addr = smac;
        hdr.ethernet.dst_addr = dmac;
    }

    /*
    action l3_forward_in(bit<9> port, mac_addr_t smac, mac_addr_t dmac) {
        set_egress_port(port);
        hdr.ethernet.src_addr = smac;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    */

    table l3_forward_table{
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            //l3_forward_in;
            l3_forward;
            drop;
        }
        size = 32;
        default_action = drop();
    }

    action l2_forward(bit<9> port) {
        set_egress_port(port);
    }

    table l2_forward_table{
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            l2_forward;
            drop;
        }
        size = 32;
        default_action = drop();
    }

    table forward_to_nf_table {
        actions = {
            l3_forward;
        }
        size = 1;
    }

    apply {
        hdr.metadata.type_and_update = meta.transition_type ++ 4w0;
        
        if((meta.transition_type & 0b1100) == 0 && meta.match == 1 && meta.main_flow_timeout == 0) {// 0,1,2,3
            l3_forward_table.apply();
            hdr.ethernet.ether_type = TYPE_METADATA;
        }
        else if(meta.transition_type == 7) {// 7
            drop();
        }
        else if(meta.transition_type == 8) {// 8
            l2_forward_table.apply();
        }
        else {// 0,1,6 (0,1 need go to nf)
            forward_to_nf_table.apply();
            hdr.ethernet.ether_type = TYPE_METADATA;

            if(meta.transition_type == 6) {
                hdr.metadata.type_and_update[0:0] = meta.accept;
            } 
            else if(meta.transition_type == 0) {
                if(meta.main_flow_timeout == 1)
                    hdr.metadata.type_and_update = 0x41;
                else 
                    hdr.metadata.type_and_update = 0x40;
            }
            else if(meta.transition_type == 1) { // 1
                if(meta.main_flow_timeout == 1)
                    hdr.metadata.type_and_update = 0x51;
                else 
                    hdr.metadata.type_and_update = 0x50;
            }
        }
    }
}

control KV(
        inout headers hdr,
        inout ingress_metadata meta
        ) {
    Register<bit<32>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) key3;
    Register<bit<32>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) key2;
    Register<bit<32>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) key1;
    Register<bit<8>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) key0;
    Register<bit<32>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) val1;
    Register<bit<16>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) val0;

    RegisterAction<bit<32>, flow_num_t, bit<32>>(key3) reg_key3_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, flow_num_t, bit<32>>(key2) reg_key2_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, flow_num_t, bit<32>>(key1) reg_key1_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<8>, flow_num_t, bit<8>>(key0) reg_key0_read = {
        void apply(inout bit<8> reg, out bit<8> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, flow_num_t, bit<32>>(val1) reg_val1_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<16>, flow_num_t, bit<16>>(val0) reg_val0_read = {
        void apply(inout bit<16> reg, out bit<16> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, flow_num_t, void>(key3) reg_key3_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.src_addr;
        }
    };
    RegisterAction<bit<32>, flow_num_t, void>(key2) reg_key2_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.dst_addr;
        }
    };
    RegisterAction<bit<32>, flow_num_t, void>(key1) reg_key1_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.src_port ++ hdr.metadata.dst_port;
        }
    };
    RegisterAction<bit<8>, flow_num_t, void>(key0) reg_key0_write = {
        void apply(inout bit<8> reg) {
            reg = hdr.metadata.protocol;
        }
    };
    RegisterAction<bit<32>, flow_num_t, void>(val1) reg_val1_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.wan_addr;
        }
    };
    RegisterAction<bit<16>, flow_num_t, void>(val0) reg_val0_write = {
        void apply(inout bit<16> reg) {
            reg = hdr.metadata.wan_port;
        }
    };

    action key3_read(in flow_num_t index) {
        hdr.metadata.src_addr = reg_key3_read.execute(index);
    }

    action key2_read(in flow_num_t index) {
        hdr.metadata.dst_addr = reg_key2_read.execute(index);
    }

    action key1_read(in flow_num_t index) {
        bit<32>tmp = reg_key1_read.execute(index);
        hdr.metadata.src_port = tmp[31:16];
        hdr.metadata.dst_port = tmp[15:0];
    }

    action key0_read(in flow_num_t index) {
        hdr.metadata.protocol = reg_key0_read.execute(index);
    }

    action val1_read(in flow_num_t index) {
        hdr.metadata.wan_addr = reg_val1_read.execute(index);
    }

    action val0_read(in flow_num_t index) {
        hdr.metadata.wan_port= reg_val0_read.execute(index);
    }
    
    action key3_write(in flow_num_t index) {
        reg_key3_write.execute(index);
    }

    action key2_write(in flow_num_t index) {
        reg_key2_write.execute(index);
    }

    action key1_write(in flow_num_t index) {
        reg_key1_write.execute(index);
    }

    action key0_write(in flow_num_t index) {
        reg_key0_write.execute(index);
    }

    action val1_write(in flow_num_t index) {
        reg_val1_write.execute(index);
    }

    action val0_write(in flow_num_t index) {
        reg_val0_write.execute(index);
    }

    apply {
        if (meta.transition_type == 6 || (meta.transition_type == 0 && meta.all_flow_timeout == 1)) {
            key3_write(meta.index_lo);
            key0_write(meta.index_lo);
            key1_write(meta.index_lo);
            key2_write(meta.index_lo);
            
        }
        else{// 1 || (0 && alltimeout == 0)
            key3_read(meta.index_lo);
            key0_read(meta.index_lo);
            key1_read(meta.index_lo);
            key2_read(meta.index_lo);
        }
        // 对于LB，FireWall，FlowCounter，RateLimiter，下面对val的读写可以做定制
        if(meta.transition_type == 6) {
            val1_write(meta.index_lo);
            val0_write(meta.index_lo);
        }
        else{
            val1_read(meta.index_lo);
            val0_read(meta.index_lo);
        }
    }
}

control Ingress(
        inout headers hdr,
        inout ingress_metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    Register<time_t, flow_num_t>(1, 0) get_update_timeout_helper; 

    Hash<bit<SHARED_SWITCH_FLOW_NUM_LOG>>(HashAlgorithm_t.CRC32) hashmap0;
    Hash<bit<SHARED_SWITCH_FLOW_NUM_LOG>>(HashAlgorithm_t.CRC32) hashmap1;
    
    Register<version_t, flow_num_t>((bit<32>)SWITCH_FLOW_NUM, 0) version;

    // MAX_SIZE = 286720
    Register<time_t, flow_num_t>((bit<32>)SWITCH_FLOW_NUM, 0) all_flow_timestamp;

    Register<time_t, flow_num_t>((bit<32>)SWITCH_FLOW_NUM, 0) main_flow_timestamp;

    RegisterAction<time_t, flow_num_t, bit<1>>(get_update_timeout_helper) reg_get_update_timeout = {
        void apply(inout time_t unused, out bit<1> ret) {
            if(meta.delta_time < 0 || meta.delta_time > HALF_AGING_TIME)
                ret = 1;
            else 
                ret = 0;
        }
    };

    RegisterAction<version_t, flow_num_t, version_t>(version) reg_version_read = {
        void apply(inout version_t reg_version, out version_t ret) {
            ret = reg_version;
        }
    };

    RegisterAction<version_t, flow_num_t, version_t>(version) reg_version_update_and_get_diff = {
        void apply(inout version_t reg_version, out version_t ret) {
            ret = hdr.metadata.version - reg_version;
            if(hdr.metadata.version - reg_version == 1 && meta.update_timeout == 0) {
                reg_version = hdr.metadata.version;
            }
        }
    };

    RegisterAction<time_t, flow_num_t, bit<1>>(all_flow_timestamp) reg_forward_update_all_flow_timestamp = {
        void apply(inout time_t reg_time, out bit<1> ret) {
            if(meta.time - reg_time > AGING_TIME) {
                ret = 1;
            }
            else {
                ret = 0;
            }
            reg_time = meta.time;
        }
    };

    RegisterAction<time_t, flow_num_t, bit<1>>(all_flow_timestamp) reg_backward_update_all_flow_timestamp = {
        void apply(inout time_t reg_time, out bit<1> ret) {
            if(meta.time - reg_time > AGING_TIME) {
                ret = 1;
            }
            else {
                ret = 0;
                reg_time = meta.time;
            }
        }
    };

    //分成两个，一个是time，只有更不更新两种选择，另一个是history，记录是否曾timeout，BINGO~
    RegisterAction<time_t, flow_num_t, void>(main_flow_timestamp) reg_force_update_mainflow_timeout = {
        void apply(inout time_t reg_time) {
            reg_time = meta.time;
        } 
    };
    RegisterAction<time_t, flow_num_t, bit<1>>(main_flow_timestamp) reg_read_mainflow_timeout = {
        void apply(inout time_t reg_time, out bit<1> ret) {
            if(meta.time - reg_time > AGING_TIME) {
                ret = 1;
            }
            else {
                ret = 0;
            }
        } 
    };
    RegisterAction<time_t, flow_num_t, bit<1>>(main_flow_timestamp) reg_update_when_no_timeout = {
        void apply(inout time_t reg_time, out bit<1> ret) {
            if(meta.time - reg_time > AGING_TIME) {
                ret = 1;
            }
            else {
                ret = 0;
                reg_time = meta.time;
            }
        }
    };
    /*
    RegisterAction<time_t, flow_num_t, bit<1>>(main_flow_timestamp) reg_main_flow_timestamp = {
        void apply(inout time_t reg_time, out bit<1> ret) {
            if(meta.time - reg_time > AGING_TIME) {
                ret = 1;
            }
            else {
                ret = 0;
            }
            if(meta.match == 1)
                reg_time = meta.time;
        }
    };
    */

    KV() kv0;
    KV() kv1;
    KV() kv2;
    KV() kv3;

    /*
    meta.transition_type 4
    meta.ingress_end 1
    hdr.metadata.index 18
    hdr.metadata.version 8
    meta.all_flow_timeout 1
    meta.accept 1
    */
    apply {
        // stage 0
        // 检查parse和checksum
        if(ig_intr_prsr_md.parser_err != 0 || meta.metadata_checksum_err) {  // metadata checksum error
            meta.transition_type = 7;
            meta.ingress_end = true;
        }
        else {
            if(meta.transition_type == 0 || meta.transition_type == 1 || meta.transition_type == 6) {
                meta.ingress_end = false;
            }
            else {//2,3,8
                meta.ingress_end = true;
            }
        }

        /// Packet with type 2,3,8 ends here 

        meta.delta_time = meta.time - hdr.metadata.switch_time;// stage 0
        
        // stage 1
        if(meta.ingress_end == false) {
            ipv4_flow_id_t id = meta.id;
            if(meta.transition_type == 0) {
#ifdef NAT_TEST
                hdr.metadata.index = 1;
#else 
                hdr.metadata.index[SHARED_SWITCH_FLOW_NUM_LOG-1:0] = hashmap0.get({id.src_addr, id.dst_addr, id.src_port, id.dst_port, id.protocol, id.zero});
#endif
                //写成index = (bit<16>)hashmap会多占用一个stage，因为index高位需要赋0，而0不是凭空而来，需要一个额外stage
            }
            else if(meta.transition_type == 1) {
                hdr.metadata.index[SHARED_SWITCH_FLOW_NUM_LOG-1:0] = hashmap1.get({id.dst_addr, id.dst_port});
            }
            else if(meta.transition_type == 6) {
                if(hdr.metadata.type_and_update[0:0] == 1)  // force update
                    meta.update_timeout = 0;
                else                        // update when the packet is not too old 
                    meta.update_timeout = reg_get_update_timeout.execute(0);
            }
        }
        
        // stage 2
        if(meta.ingress_end == false) {// 0/1/6

            meta.index_lo = hdr.metadata.index & (SWITCH_FLOW_NUM_PER_REG - 1);
            meta.index_hi = hdr.metadata.index[SHARED_SWITCH_FLOW_NUM_LOG-1:SHARED_SWITCH_FLOW_NUM_PER_REG_LOG];

            if(meta.transition_type != 6) {
                hdr.metadata.version = reg_version_read.execute(hdr.metadata.index);
            }
            else {
                meta.version_diff = reg_version_update_and_get_diff.execute(hdr.metadata.index);
            }
        }
    
        // stage 3
        // reg "all_flow_timestamp"
        if(meta.ingress_end == false) {
            if(meta.transition_type == 6) {
                    
                if(meta.version_diff == 1 && meta.update_timeout == 0) {
                    meta.all_flow_timeout = reg_forward_update_all_flow_timestamp.execute(hdr.metadata.index);
                }
                else // 修改不同的位域不要用else if!!!!!!
                    meta.ingress_end = true;  

                if(meta.version_diff != 0 && meta.version_diff != 1) // != 0, 1
                    meta.transition_type = 7;// no response
                else if(meta.version_diff == 1 && meta.update_timeout == 1)
                    meta.accept = 0; //hdr.metadata.type = 0b0011_0000;// reject
                else 
                    meta.accept = 1; //hdr.metadata.type = 0b0010_0000;// accept
                // switch(transition_type, update_timeout):
                //      0 , _   : end, send accept
                //      1 , 1   : end, send reject (Packet of the same update will also receive reject later)
                //      1 , 0   : go down, send accept
                //      _ , _   : end, no response
            }
            else if(hdr.metadata.version == 0) {
                meta.all_flow_timeout = 0;
                // 多半还没加载规则，禁止抢占
            }
            else if(meta.transition_type == 0) {
                meta.all_flow_timeout = reg_forward_update_all_flow_timestamp.execute(hdr.metadata.index);
            }
            else {// 1
                meta.all_flow_timeout = reg_backward_update_all_flow_timestamp.execute(hdr.metadata.index);
            }
        }
        

        meta.need_match = 0;
        meta.match = 1;

        // stage 6
        if ((meta.transition_type == 0 && meta.all_flow_timeout == 0) || meta.transition_type == 1) {
            meta.need_match = 1;
        }
        // stage 4,5 (因为一个stage最多4个register)
        // register "map"
        // RegisterAction会两两合并
        if(meta.ingress_end == false) {
            if(meta.index_hi == 0) kv0.apply(hdr, meta);
            else if(meta.index_hi == 1) kv1.apply(hdr, meta);
            //else if(meta.index_hi == 2) kv2.apply(hdr, meta);
            //else if(meta.index_hi == 3) kv3.apply(hdr, meta);
            

            // 副流超时时，禁止任何反向流量
            if(meta.transition_type == 1 && meta.all_flow_timeout == 1) {
                meta.transition_type = 7;
                meta.ingress_end = true;
            }
        }
        
        /*
        if(ig_intr_md.resubmit_flag == 0) {
            // this assignment make it valid
            ig_intr_dprs_md.resubmit_type = 0;
        }
        */
        
        if(meta.need_match == 1 && hdr.metadata.protocol != meta.id.protocol) {
            meta.match = 0;
        }

        if(meta.transition_type == 0) {
            meta.cmp.src_addr = hdr.metadata.src_addr;
            meta.cmp.dst_addr = hdr.metadata.dst_addr;
            meta.cmp.src_port = hdr.metadata.src_port;
            meta.cmp.dst_port = hdr.metadata.dst_port;
        }
        else {
            meta.cmp.src_addr = hdr.metadata.dst_addr;
            meta.cmp.dst_addr = hdr.metadata.wan_addr;
            meta.cmp.src_port = hdr.metadata.dst_port;
            meta.cmp.dst_port = hdr.metadata.wan_port;
        }
        
        // 综合match的结果 
        
        
            // 这个if被分成了两个stage，注释前在上一个stage(5)，注释后在下一个stage(6)
            // if的判断结果可以在stage间传递
        if(meta.need_match == 1) {
            if(meta.cmp.src_addr != meta.id.src_addr)
                meta.match = 0;
            else if(meta.cmp.dst_addr != meta.id.dst_addr)
                meta.match = 0;
            else if(meta.cmp.src_port != meta.id.src_port || meta.cmp.dst_port != meta.id.dst_port)
                meta.match = 0;
        }
            

        meta.main_flow_timeout = 0;
        
        // stage 8
        // register main_flow_time
        if(meta.ingress_end == false) {// for type 0/1/6
            if(meta.need_match == 0) {
                meta.main_flow_timeout = 0;
                reg_force_update_mainflow_timeout.execute(hdr.metadata.index);
            }
            else if(meta.match == 1) {
                meta.main_flow_timeout = reg_update_when_no_timeout.execute(hdr.metadata.index);
            }
            else {
                meta.main_flow_timeout = reg_read_mainflow_timeout.execute(hdr.metadata.index);
            }
            
            // 我们不怕时间戳回滚，因为：
            //  0. 大不了滚到一半，server更新一下
            //  1. 主流超时后，副流必向server通知更新
            //  2. 如果主流超时后，一段时间内没有副流流量，那么会导致副流超时：
            //      如果下一个包是正向包，必然抢占
            //      如果下一个包是反向包，必然被丢掉，除非正好回滚到对应时间
        }
        
        // stage 9
        send_out.apply(hdr, meta, ig_intr_md, ig_intr_dprs_md, ig_intr_tm_md);

        /*
        if(hdr.ethernet.dst_addr[7:0] == 1) {
            hdr.ethernet.ether_type = 0;
        }
        if(hdr.ethernet.ether_type == hdr.tcp.src_port) {
            hdr.ipv4.protocol = 0;
        }
        */
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control IngressDeparser(
        packet_out packet,
        inout headers hdr,
        in ingress_metadata meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    apply{
        packet.emit(hdr.ethernet);
        packet.emit(hdr.metadata);
        packet.emit(hdr.ipv4);
    }
}

parser EgressParser(packet_in packet,
               out headers hdr,
               out egress_metadata meta,
               out egress_intrinsic_metadata_t eg_intr_md) {

    Checksum() L4_csum;

    state start {
        packet.extract(eg_intr_md);//这一句和bypass_egress必有其一，否则包会被丢
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {//没检查MAC addr，没必要
            TYPE_METADATA   :   parse_metadata;
            default         :   accept;
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata);
        meta.transition_type = hdr.metadata.type_and_update[7:4];
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        L4_csum.subtract({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});

        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL    :   parse_tcp;
            UDP_PROTOCOL    :   parse_udp;
            // no other
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);

        L4_csum.subtract({hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.checksum});
        L4_csum.subtract_all_and_deposit(meta.L4_partial_complement_sum);

        meta.is_tcp = true;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);

        L4_csum.subtract({hdr.udp.src_port, hdr.udp.dst_port, hdr.udp.checksum});
        L4_csum.subtract_all_and_deposit(meta.L4_partial_complement_sum);

        meta.is_tcp = false;
        transition accept;
    }
}

control Egress(
        inout headers hdr,
        inout egress_metadata meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply { 
        // By default: drop packets with "eg_intr_prsr_md.parser_err != 0"
        if(hdr.ethernet.ether_type != TYPE_METADATA) return;
        
        
        if(hdr.udp.isValid() && hdr.udp.checksum != 0) 
            meta.update_udp_checksum = true;
        else
            meta.update_udp_checksum = false;


        if((meta.transition_type & 0b1100) == 0) {//0, 1, 2, 3
            hdr.metadata.setInvalid();
            hdr.ethernet.ether_type = TYPE_IPV4;

            if(meta.transition_type == 0) {
                hdr.ipv4.src_addr = hdr.metadata.wan_addr;
                if(meta.is_tcp)
                    hdr.tcp.src_port = hdr.metadata.wan_port;
                else 
                    hdr.udp.src_port = hdr.metadata.wan_port;
            }
            else if(meta.transition_type == 1) {
                hdr.ipv4.dst_addr = hdr.metadata.src_addr;
                if(meta.is_tcp)
                    hdr.tcp.dst_port = hdr.metadata.src_port;
                else 
                    hdr.udp.src_port = hdr.metadata.src_port;
            }
        }
        else if((meta.transition_type & 0b1110) == 4) {// 4, 5
            hdr.metadata.src_addr = hdr.ipv4.src_addr;
            hdr.metadata.dst_addr = hdr.ipv4.dst_addr;
            hdr.metadata.protocol = hdr.ipv4.protocol;
            hdr.metadata.zero = 0;
            if(meta.is_tcp) {
                hdr.metadata.src_port = hdr.tcp.src_port;
                hdr.metadata.dst_port = hdr.tcp.dst_port;
            }
            else {
                hdr.metadata.src_port = hdr.udp.src_port;
                hdr.metadata.dst_port = hdr.udp.dst_port;
            }
        }
    }
}

control ComputeChecksum(inout headers hdr, in egress_metadata meta) {

    Checksum() csum16;

    apply {
        if(hdr.metadata.isValid()) {
            hdr.metadata.checksum = csum16.update(
                {hdr.metadata.src_addr, 
                hdr.metadata.dst_addr, 
                hdr.metadata.src_port, 
                hdr.metadata.dst_port, 
                hdr.metadata.protocol,
                hdr.metadata.zero,

                hdr.metadata.wan_addr,
                hdr.metadata.wan_port,

                hdr.metadata.version,
                hdr.metadata.type_and_update,

                hdr.metadata.index,
                hdr.metadata.switch_time}
            );
        }
        
        if(hdr.ipv4.isValid()) {
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
        
        if(hdr.tcp.isValid()) {
            hdr.tcp.checksum = csum16.update(
                {hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                meta.L4_partial_complement_sum}
            );
        }
        
        if(meta.update_udp_checksum) {
            hdr.udp.checksum = csum16.update(
                {hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.udp.src_port,
                hdr.udp.dst_port,
                meta.L4_partial_complement_sum}
            );
        }
    }
}

control EgressDeparser(packet_out packet,
                  inout headers hdr,
                  in egress_metadata meta,
                  in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
            
    apply { 
        ComputeChecksum.apply(hdr, meta);

        packet.emit(hdr.ethernet);
        packet.emit(hdr.metadata);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

Pipeline(IngressParser(), Ingress(), IngressDeparser(), EgressParser(), Egress(), EgressDeparser()) pipe;

Switch(pipe) main;
