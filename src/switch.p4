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

const bit<8>  TCP_PROTOCOL = 0x06;
const bit<8>  UDP_PROTOCOL = 0x11;

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_METADATA = SHARED_TYPE_METADATA;

//you can change these by tables to support dynamic & multiple LAN address allocation
const ip4_addr_t LAN_ADDR = SHARED_LAN_ADDR;// 192.168.0.0
const ip4_addr_t LAN_ADDR_MASK = SHARED_LAN_ADDR_MASK;// /24
const ip4_addr_t NAT_ADDR = SHARED_NAT_ADDR;// 192.168.2.254

const port_t PORT_MIN = SHARED_PORT_MIN;
const port_t PORT_MAX = SHARED_PORT_MAX;// included
const port_t SWITCH_PORT_NUM = SHARED_SWITCH_PORT_NUM;
const port_t TOTAL_PORT_NUM = SHARED_PORT_MAX - SHARED_PORT_MIN + 1;

const time_t AGING_TIME = SHARED_AGING_TIME_FOR_SWITCH;// 1 s
const time_t HALF_AGING_TIME = SHARED_AGING_TIME_FOR_SWITCH / 2;

const mac_addr_t SWITCH_INNER_MAC = SHARED_SWITCH_INNER_MAC;
const mac_addr_t NF_INNER_MAC = SHARED_NF_INNER_MAC;

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

    port_t      switch_port;
    version_t   version;

    bit<8>      type;// 8w0b1000_0000 to_in, 8w0b0100_0000 to_out, 8w0b0010_0000 update(accept), 8w0b0011_0000 update(refuse)
    

    index_t     index; // index is the hash value of flow id
    time_t      switch_time;// 因为一个ACK返回的时候wait_entry可能已经没了，所以时间需要记录在packet里
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

struct nf_port_t{
    bit<9>  nf_port;
    bit<2>  port_type; 
    bit<5>  unused;
}

struct metadata {
    /* parser -> ingress */
    bool            is_tcp;

    bool            metadata_checksum_err;
    bit<16>         L4_partial_complement_sum;
    
    nf_port_t       nf_port_hdr;

    /* ingress.get_transition_type -> ingress */
    bit<4>          transition_type;    // 0:in->out/nf, 1:out->in/nf, 2:nf->out, 3:nf->in, 4:in->nf, 5:out->nf, 6:update, 7:drop
    index_t         reverse_index;  
    //bool            mac_match;

    /* ingress */
    bool            ingress_end;

    bit<1>          update_timeout;
    bit<1>          all_flow_timeout;
    bit<1>          main_flow_timeout;

    // packet info
    ipv4_flow_id_t  id;          
    time_t          time;
    time_t          delta_time;
    // register

    bit<1>          match;

    bit<9>          version_diff;
    bool            update_udp_checksum;

    /* ingress checksum -> egress checksum */
    bool            tmp_bool0;
    bool            tmp_bool1;
    bool            tmp_bool2;
    bool            tmp_bool3;
    bool            tmp_bool4;

}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser IngressParser(packet_in packet,
               out headers hdr,
               out metadata meta,
               out ingress_intrinsic_metadata_t ig_intr_md) {

    /*
    关于校验和，我这样处理：
        metadata checksum：检验并更新
        ip checksum：不检验，只更新（因为很多情况下没人在乎ip checksum）
        tcp/udp checksum：只增量更新（udp为0不更新）
    */
    Checksum() metadata_csum;
    Checksum() L4_csum;

    state start {
        packet.extract(ig_intr_md);

        meta.time = ig_intr_md.ingress_mac_tstamp[47:16];// truncate
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
            TYPE_IPV4 ++ 2w1:   parse_ipv4_from_WAN;
            default         :   parse_other_flow;
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata);
        metadata_csum.add(hdr.metadata);
        meta.metadata_checksum_err = metadata_csum.verify();
        transition select(hdr.metadata.type) {
            8w0b010_00000 :   mark_type_2;
            8w0b100_00000 :   mark_type_3;
            8w0b001_00000 :   mark_type_6;
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

    state parse_ipv4_from_WAN {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        transition select(ip.dst_addr) {
            NAT_ADDR    :   maybe_type_1;// out->in
            default     :   parse_other_flow;// out->out
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
        transition parse_inner_ipv4;
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
        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.ipv4);

        L4_csum.subtract({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});

        // fill id
        meta.id.src_addr = hdr.ipv4.src_addr;
        meta.id.dst_addr = hdr.ipv4.dst_addr;
        meta.id.protocol = hdr.ipv4.protocol;
        meta.id.zero = 0;

        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL : parse_tcp;
            UDP_PROTOCOL : parse_udp;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        // The result is complement sum of all fields except src_port & dst_port. (Of course, "checksum" is not in "all")
        L4_csum.subtract({hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.checksum});
        L4_csum.subtract_all_and_deposit(meta.L4_partial_complement_sum);
        //meta.L4_partial_complement_sum = L4_csum.get();
        meta.is_tcp = true;

        // fill id
        meta.id.src_port = hdr.tcp.src_port;
        meta.id.dst_port = hdr.tcp.dst_port;

        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        //L4_csum.subtract({hdr.udp.src_port, hdr.udp.dst_port, hdr.udp.checksum});
        //meta.L4_partial_complement_sum = L4_csum.get();
        L4_csum.subtract({hdr.udp.src_port, hdr.udp.dst_port, hdr.udp.checksum});
        L4_csum.subtract_all_and_deposit(meta.L4_partial_complement_sum);
        meta.is_tcp = false;

        // fill id
        meta.id.src_port = hdr.udp.src_port;
        meta.id.dst_port = hdr.udp.dst_port;

        transition accept;
    }

    state parse_other_flow {
        meta.transition_type = 8;
        transition accept;
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control check_eport(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md) {

    Register<bit<16>, bit<16>>(1) help1;
    Register<bit<16>, bit<16>>(1) help2;
    Register<bit<16>, bit<16>>(1) help3;// 所有RegisterAction共享SALU，一个Register只有一个SALU

    RegisterAction<bit<16>, bit<16>, bit<4>>(help1) reg_check_tcp_eport = {
        void apply(inout bit<16> reg, out bit<4> ret) {
            if(PORT_MIN <= hdr.tcp.dst_port && hdr.tcp.dst_port <= PORT_MAX)
                ret = 0;
            else 
                ret = 7;// drop
        }
    };
    RegisterAction<bit<16>, bit<16>, bit<4>>(help2) reg_check_udp_eport = {
        void apply(inout bit<16> reg, out bit<4> ret) {
            if(PORT_MIN <= hdr.udp.dst_port && hdr.udp.dst_port <= PORT_MAX)
                ret = 0;
            else 
                ret = 7;
        }
    };
    RegisterAction<bit<16>, bit<16>, bit<4>>(help3) reg_check_update_eport = {
        void apply(inout bit<16> reg, out bit<4> ret) {
            if(PORT_MIN <= hdr.metadata.switch_port && hdr.metadata.switch_port <= PORT_MAX)
                ret = 0;
            else 
                ret = 7;
        }
    };

    action check_tcp_eport() {
        bit<4>tmp = reg_check_tcp_eport.execute(0);
        meta.transition_type = meta.transition_type | tmp;
        meta.ingress_end = (bool)tmp[0:0];
        meta.reverse_index = hdr.tcp.dst_port - PORT_MIN;
    }

    action check_udp_eport() {
        bit<4>tmp = reg_check_udp_eport.execute(0);
        meta.transition_type = meta.transition_type | tmp;
        meta.ingress_end = (bool)tmp[0:0];
        meta.reverse_index = hdr.udp.dst_port - PORT_MIN;
    }

    action check_update_eport() {
        bit<4>tmp = reg_check_update_eport.execute(0);
        meta.transition_type = meta.transition_type | tmp;
        meta.ingress_end = (bool)tmp[0:0];
        meta.reverse_index = hdr.metadata.switch_port - PORT_MIN;
    }


    apply {
        if(meta.transition_type == 0) {
            meta.ingress_end = false;
        }
        else if(meta.transition_type == 1) {
            if(meta.is_tcp) 
                check_tcp_eport();
            else 
                check_udp_eport();
        }
        else if((meta.transition_type & 0b1110) == 2) {//2,3
            meta.ingress_end = true;
        }
        else if(meta.transition_type == 6) {
            check_update_eport();
        }    
        else if(meta.transition_type == 8) {
            meta.ingress_end = true;
        }
    }
}

control send_out(
        inout headers hdr,
        inout metadata meta,
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

    action l3_forward_out(bit<9> port, mac_addr_t smac, mac_addr_t dmac) {
        set_egress_port(port);
        hdr.ethernet.src_addr = smac;
        hdr.ethernet.dst_addr = dmac;
    }

    action l3_forward_in(bit<9> port, mac_addr_t smac, mac_addr_t dmac) {
        set_egress_port(port);
        hdr.ethernet.src_addr = smac;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table l3_forward_table{
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            l3_forward_in;
            l3_forward_out;
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

    apply {
        if(hdr.udp.isValid() && hdr.udp.checksum != 0) 
            meta.update_udp_checksum = true;
        else
            meta.update_udp_checksum = false;

        if((meta.transition_type & 0b1100) == 0) {// 0, 1, 2, 3
            hdr.metadata.setInvalid();
            hdr.ethernet.ether_type = TYPE_IPV4;

            l3_forward_table.apply();
        }
        else if((meta.transition_type & 0b1110) == 4){// 4, 5
            
            hdr.ethernet.ether_type = TYPE_METADATA;
            hdr.ethernet.src_addr = 48w1;
            hdr.ethernet.dst_addr = 48w2;

            hdr.metadata.src_addr = meta.id.src_addr;
            hdr.metadata.dst_addr = meta.id.dst_addr;
            hdr.metadata.src_port = meta.id.src_port;
            hdr.metadata.dst_port = meta.id.dst_port;
            hdr.metadata.protocol = meta.id.protocol;
            hdr.metadata.zero = 0;

            //hdr.metadata.switch_port = switch_port;
            
            //hdr.metadata.is_to_in
            //hdr.metadata.is_to_out
            //hdr.metadata.is_update = timeout;
            
            //hdr.metadata.version = version;
            //hdr.metadata.index = index;
            hdr.metadata.switch_time = meta.time;
            hdr.metadata.checksum = 0;
            
            set_egress_port(meta.nf_port_hdr.nf_port);
            
            if(meta.transition_type == 4) {
                //hdr.metadata.switch_port = meta.reg_map.eport;
                //hdr.metadata.version

                if(meta.main_flow_timeout == 0) 
                    hdr.metadata.type = 8w0b0100_0000;
                else 
                    hdr.metadata.type = 8w0b0110_0000;
                
                //hdr.metadata.index
            }
            else if(meta.transition_type == 5){
                hdr.metadata.switch_port = 0;
                hdr.metadata.version = 0;

                hdr.metadata.type = 8w0b1000_0000;

                hdr.metadata.index = 0;
            }
        }
        else if(meta.transition_type == 6) {
            hdr.ethernet.src_addr = 48w1;
            hdr.ethernet.dst_addr = 48w2;

            set_egress_port(meta.nf_port_hdr.nf_port);
        }
        else if(meta.transition_type == 7) {
            drop();
        }
        else if(meta.transition_type == 8) {
            l2_forward_table.apply();
        }
    }
}

control Ingress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    Register<time_t, index_t>(1, 0) get_update_timeout_helper; 

    Hash<bit<SWITCH_PORT_NUM_LOG>>(HashAlgorithm_t.CRC16) hashmap;
    
    Register<version_t, index_t>((bit<32>)SWITCH_PORT_NUM, 0) version;

    Register<index_t, index_t>((bit<32>)TOTAL_PORT_NUM, 0) reverse_map;

    Register<time_t, index_t>((bit<32>)SWITCH_PORT_NUM, 0) all_flow_timestamp;

    Register<bit<32>, index_t>((bit<32>)SWITCH_PORT_NUM, 0) key3;
    Register<bit<32>, index_t>((bit<32>)SWITCH_PORT_NUM, 0) key2;
    Register<bit<32>, index_t>((bit<32>)SWITCH_PORT_NUM, 0) key1;
    Register<bit<8>, index_t>((bit<32>)SWITCH_PORT_NUM, 0) key0;
    Register<bit<16>, index_t>((bit<32>)SWITCH_PORT_NUM, 0) val;
    // TODO：time后续可以改成8bit
    Register<time_t, index_t>((bit<32>)SWITCH_PORT_NUM, 0) main_flow_timestamp;

    RegisterAction<time_t, index_t, bit<1>>(get_update_timeout_helper) reg_get_update_timeout = {
        void apply(inout time_t unused, out bit<1> ret) {
            if(meta.delta_time > HALF_AGING_TIME)
                ret = 1;
            else 
                ret = 0;
        }
    };

    RegisterAction<version_t, index_t, version_t>(version) reg_version = {
        void apply(inout version_t reg_version, out version_t ret) {
            ret = reg_version - hdr.metadata.version;
            if(hdr.metadata.version - reg_version == 1 && meta.update_timeout == 0) {
                reg_version = hdr.metadata.version;
            }
        }
    };

    RegisterAction<index_t, index_t, index_t>(reverse_map) reg_reverse_map_read_or_update = {
        void apply(inout index_t reg_index, out index_t ret) {
            if(meta.version_diff == 9w256) {// transition_type == 1, read,也可以用meta.version_diff==9w256
                ret = reg_index;
            }
            else {
                ret = 0;// useless, 消除WARNING
            }
            if(meta.version_diff == 9w255/*8w-1*/) {
                reg_index = hdr.metadata.index;
            }
        }
    };

    RegisterAction<time_t, index_t, bit<1>>(all_flow_timestamp) reg_all_flow_timestamp = {
        void apply(inout bit<32> reg_time, out bit<1> ret) {
            if(meta.time - reg_time > AGING_TIME)
                ret = 1;
            else 
                ret = 0;
            reg_time = meta.time;
        }
    };
    

    RegisterAction<bit<32>, index_t, bit<32>>(key3) reg_key3_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(key2) reg_key2_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(key1) reg_key1_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<8>, index_t, bit<8>>(key0) reg_key0_read = {
        void apply(inout bit<8> reg, out bit<8> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<16>, index_t, bit<16>>(val) reg_val_read = {
        void apply(inout bit<16> reg, out bit<16> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(key3) reg_key3_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.src_addr;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(key2) reg_key2_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.dst_addr;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(key1) reg_key1_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.src_port ++ hdr.metadata.dst_port;
        }
    };
    RegisterAction<bit<8>, index_t, bit<8>>(key0) reg_key0_write = {
        void apply(inout bit<8> reg) {
            reg = hdr.metadata.protocol;
        }
    };
    RegisterAction<bit<16>, index_t, bit<16>>(val) reg_val_write = {
        void apply(inout bit<16> reg) {
            reg = hdr.metadata.switch_port;
        }
    };

    //分成两个，一个是time，只有更不更新两种选择，另一个是history，记录是否曾timeout，BINGO~
    RegisterAction<time_t, index_t, bit<1>>(main_flow_timestamp) reg_main_flow_timestamp = {
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

    action reverse_map_read() {
        hdr.metadata.index = reg_reverse_map_read_or_update.execute(meta.reverse_index);
    }

    action reverse_map_write() {
        reg_reverse_map_read_or_update.execute(meta.reverse_index);
        //hdr.metadata.index = 0xf;//////////////////////////////////////////////////
    }

    action key3_read(in index_t index) {
        hdr.metadata.src_addr = reg_key3_read.execute(index);
    }

    action key2_read(in index_t index) {
        hdr.metadata.dst_addr = reg_key2_read.execute(index);
    }

    action key1_read(in index_t index) {
        bit<32>tmp = reg_key1_read.execute(index);
        hdr.metadata.src_port = tmp[31:16];
        hdr.metadata.dst_port = tmp[15:0];
    }

    action key0_read(in index_t index) {
        hdr.metadata.protocol = reg_key0_read.execute(index);
        hdr.metadata.zero = 0;
    }

    action val_read(in index_t index) {
        hdr.metadata.switch_port = reg_val_read.execute(index);
    }

    action key3_write(in index_t index) {
        reg_key3_write.execute(index);
    }

    action key2_write(in index_t index) {
        reg_key2_write.execute(index);
    }

    action key1_write(in index_t index) {
        reg_key1_write.execute(index);
    }

    action key0_write(in index_t index) {
        reg_key0_write.execute(index);
    }

    action val_write(in index_t index) {
        reg_val_write.execute(index);
    }

    apply {
        // bypass_egress
        ig_intr_tm_md.bypass_egress = 1;

        // set valid 
        hdr.metadata.setValid();

        // 检查parse和checksum
        if(ig_intr_prsr_md.parser_err != 0 ||                               // parse error
            (hdr.metadata.isValid() && meta.metadata_checksum_err)) {  // metadata checksum error
            meta.transition_type = 7;
            meta.ingress_end = true;
        }
        else {
            // 检查反向流的eport合法性
            check_eport.apply(hdr, meta, ig_intr_md);//不能放外面，因为有对ingress_end赋值
        }

        /// Packet with type 2,3,8 ends here 

        meta.delta_time = meta.time - hdr.metadata.switch_time;// stage 0

        // stage 1
        if(meta.ingress_end == false) {
            if(meta.transition_type == 0) {
                meta.update_timeout = 1;
                hdr.metadata.version = 0;
                ipv4_flow_id_t id = meta.id;
                hdr.metadata.index = (index_t) hashmap.get({id.src_addr, id.dst_addr, id.src_port, id.dst_port, id.protocol, id.zero});
                // 把hash直接做register的index(置于同一个stage)好像会出问题
            }
            else if(meta.transition_type == 6) {
                meta.update_timeout = reg_get_update_timeout.execute(0);
            }
        }
        
        // stage 2
        if(meta.ingress_end == false) {// 0/6
            if(meta.transition_type == 0) {
                hdr.metadata.version = reg_version.execute(hdr.metadata.index);
            }
            else if(meta.transition_type == 1) {
                meta.version_diff = 9w256;
            }
            else if(meta.transition_type == 6) {
                meta.version_diff = (bit<9>)reg_version.execute(hdr.metadata.index);
            }
        }

        // stage 3
        if(meta.ingress_end == false && meta.transition_type == 6) {
            if(meta.version_diff != 9w255/*8w-1*/ || meta.update_timeout != 0) // 修改不同的位域不要用else if!!!!!!
                meta.ingress_end = true;  

            if(meta.version_diff != 0 && meta.version_diff != 9w255) // != 0, 1
                meta.transition_type = 7;// no response
            else if(meta.version_diff == 9w255 && meta.update_timeout == 1)
                hdr.metadata.type = 0b0011_0000;// refuse
            else 
                hdr.metadata.type = 0b0010_0000;// accept
            // switch(transition_type, update_timeout):
            //      0 , _   : end, send accept
            //      -1, 1   : end, send refuse
            //      -1, 0   : go down, send accept
            //      _ , _   : end, no response
        }

        // stage 4
        // register "reverse_map"
        if(meta.ingress_end == false) {
            if (meta.transition_type == 1) {
                reverse_map_read();// 1的index在这里获得
            }
            else if(meta.transition_type == 6) {
                reverse_map_write();// 
            }
        }

        // stage 5
        // register "all_flow_timestamp"
        if(meta.ingress_end == false) {
#ifdef THERE_MUST_BE_FORWARD_HEARTBEATS
            if (meta.transition_type != 1) {
#endif
                meta.all_flow_timeout = reg_all_flow_timestamp.execute(hdr.metadata.index);
#ifdef THERE_MUST_BE_FORWARD_HEARTBEATS
            }
#endif
            // 1号也得更新：考虑只有主流且主流只有反向流的情况
        }
        
        // stage 6
        // register "map"
        // RegisterAction会两两合并
        if(meta.ingress_end == false) {
            if (meta.transition_type == 6) {
                key3_write(hdr.metadata.index);
                key2_write(hdr.metadata.index);
                key1_write(hdr.metadata.index);
                key0_write(hdr.metadata.index);
                val_write(hdr.metadata.index);
            }
            else if(meta.transition_type == 0 && meta.all_flow_timeout == 1) {
                key3_write(hdr.metadata.index);
                key2_write(hdr.metadata.index);
                key1_write(hdr.metadata.index);
                key0_write(hdr.metadata.index);
                val_read(hdr.metadata.index);
                // hdr.metadata.src_addr = meta.id.src_addr
                // hdr.metadata.dst_addr = meta.id.dst_addr
                // hdr.metadata.src_port = meta.id.src_port
                // hdr.metadata.dst_port = meta.id.dst_port
                // hdr.metadata.protocol = meta.id.protocol
            }
            else {// 1 || (0 && alltimeout == 0)
                key3_read(hdr.metadata.index);
                key2_read(hdr.metadata.index);
                key1_read(hdr.metadata.index);
                key0_read(hdr.metadata.index);
                val_read(hdr.metadata.index);
            }
        }
        

        /*
        ip4_addr_t src_addr_cmp;
        ip4_addr_t dst_addr_cmp;
        port_t src_port_cmp;
        port_t dst_port_cmp;

        if(meta.ingress_end == false) {
            if (meta.transition_type == 0) {
                src_addr_cmp = hdr.metadata.src_addr;
                dst_addr_cmp = hdr.metadata.dst_addr;
                src_port_cmp = hdr.metadata.src_port;
                dst_port_cmp = hdr.metadata.dst_port;
            }
            else {// For 1.   6 is OK
                src_addr_cmp = hdr.metadata.dst_addr;
                dst_addr_cmp = 0;// useless
                src_port_cmp = hdr.metadata.dst_port;
                dst_port_cmp = hdr.metadata.switch_port;
            }
        }
        // matching
        if(meta.ingress_end == false) {
            // for type 0/1/6
            if(src_addr_cmp == meta.id.src_addr)
                meta.tmp_bool3 = true;
            else 
                meta.tmp_bool3 = false;
            
            if(dst_addr_cmp == meta.id.dst_addr)
                meta.tmp_bool2 = true;
            else 
                meta.tmp_bool2 = false;

            if(src_port_cmp == meta.id.src_port && hdr.metadata.protocol == meta.id.protocol)
                meta.tmp_bool1 = true;
            else 
                meta.tmp_bool1 = false;

            if(dst_port_cmp == meta.id.dst_port)
                meta.tmp_bool0 = true;
            else 
                meta.tmp_bool0 = false;
        }   
        */

        // 综合match的结果 
        ip4_addr_t src_addr_cmp;
        ip4_addr_t dst_addr_cmp;
        port_t src_port_cmp;
        port_t dst_port_cmp;

        meta.match = 1;

        // stage 7
        if (meta.transition_type == 0 && meta.all_flow_timeout == 0) {
            src_addr_cmp = hdr.metadata.src_addr;
            dst_addr_cmp = hdr.metadata.dst_addr;
            src_port_cmp = hdr.metadata.src_port;
            dst_port_cmp = hdr.metadata.dst_port;
            if(hdr.metadata.protocol != meta.id.protocol) {
                meta.match = 0;
            }
        }
        else if(meta.transition_type == 1) {
            src_addr_cmp = hdr.metadata.dst_addr;
            dst_addr_cmp = NAT_ADDR;// useless
            src_port_cmp = hdr.metadata.dst_port;
            dst_port_cmp = hdr.metadata.switch_port;
            if(hdr.metadata.protocol != meta.id.protocol) {
                meta.match = 0;
            }
        }
        //else // For 6, match == 1
  
        // stage 8
        if((meta.transition_type == 0 && meta.all_flow_timeout == 0) || meta.transition_type == 1) {// 0/1
            if(src_addr_cmp != meta.id.src_addr)
                meta.match = 0;
            else if(dst_addr_cmp != meta.id.dst_addr)
                meta.match = 0;
            else if(src_port_cmp != meta.id.src_port || dst_port_cmp != meta.id.dst_port)
                meta.match = 0;
        }
        //else For 6, match == 1

        /// packet with type 5 ends here 

        // stage 9
        // register main_flow_time
        if(meta.ingress_end == false) {// for type 0/1/6
            if(meta.transition_type == 6 || (meta.transition_type == 0 && meta.all_flow_timeout == 1)) {
                reg_main_flow_timestamp.execute(hdr.metadata.index);
                meta.main_flow_timeout = 0;
            }
            else {
                meta.main_flow_timeout = reg_main_flow_timestamp.execute(hdr.metadata.index);
                //如果主流timeout之后又来了主流的包，也会更新时间，
                //这不妥，会导致主流恢复后又被掐断，但暂时没办法改进
                //总的来说不会影响正确性，并且是小概率事件
            }

            if(meta.transition_type == 6) {
                meta.ingress_end = true;
            }

            if(meta.transition_type == 1 && meta.match == 0) {
                if(hdr.metadata.switch_port != meta.id.dst_port) {
                    // eport is not keep by switch
                    meta.transition_type = 5;
                    meta.ingress_end = true;
                }
                else {
                    // eport is keep by switch but id mismatch
                    meta.transition_type = 7;
                    meta.ingress_end = true;
                } 
            }
        }
        
        /// packet with type 6 ends here 
        
        // stage 10
        // translate
        
        if(meta.ingress_end == false) {
            if (meta.transition_type == 0) {
                if(meta.match == 1 && meta.main_flow_timeout == 0) {
                    // translate
                    hdr.ipv4.src_addr = NAT_ADDR;
                    if(meta.is_tcp) 
                        hdr.tcp.src_port = hdr.metadata.switch_port;
                    else
                        hdr.udp.src_port = hdr.metadata.switch_port;

                    meta.ingress_end = true;
                }
                else {
                    meta.transition_type = 4;
                    meta.ingress_end = true;
                }
            }
            else {// it must be type 1
                if(meta.main_flow_timeout == 0) {// mata.match is always true
                    // reverse_translate
                    hdr.ipv4.dst_addr = hdr.metadata.src_addr;
                    if(meta.is_tcp)
                        hdr.tcp.dst_port = hdr.metadata.src_port;
                    else
                        hdr.udp.dst_port = hdr.metadata.src_port;

                    meta.ingress_end = true;
                }
                else {
                    // timeout
                    meta.transition_type = 7;
                    meta.ingress_end = true;
                }  
            }
        }
        /// packet with type 0,1,4 ends here 

        /*if(meta.transition_type == 1) {
            ig_intr_dprs_md.drop_ctl = 0;
            //meta.update_udp_checksum = true;

            ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            return;
        }*/
        //meta.nf_port_hdr.nf_port = ig_intr_md.ingress_port;
        
        send_out.apply(hdr, meta, ig_intr_md, ig_intr_dprs_md, ig_intr_tm_md);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyComputeChecksum(inout headers hdr, in metadata meta) {

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

                hdr.metadata.switch_port,

                hdr.metadata.version,
                hdr.metadata.type,

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

control IngressDeparser(
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

parser EgressParser(packet_in packet,
               out headers hdr,
               out metadata meta,
               out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        packet.extract(eg_intr_md);//这一句和bypass_egress必有其一，否则包会被丢
        transition accept;
    }
}

control Egress(
        inout headers hdr,
        inout metadata meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply { }
}

control EgressDeparser(packet_out b,
                  inout headers hdr,
                  in metadata meta,
                  in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply { }
}

Pipeline(IngressParser(), Ingress(), IngressDeparser(), EgressParser(), Egress(), EgressDeparser()) pipe;

Switch(pipe) main;
