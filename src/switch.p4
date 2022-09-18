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
const bit<8>  ICMP_PROTOCOL = 0x01;

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

const time_t AGING_TIME_US = SHARED_AGING_TIME_US;// 1 s

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

    bit<8>      type;// 8w0b100_00000 to_in, 8w0b010_00000 to_out, 8w0b001_00000 update, 
    

    index_t     index; // index is the hash value of flow id
    time_t      nf_time;// 因为一个ACK返回的时候wait_entry可能已经没了，所以时间需要记录在packet里
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

struct nf_port_t{
    bit<9>  nf_port;
    bit<7>  unused;
}

struct metadata {
    /* parser -> ingress */
    bool            is_tcp;

    bool            metadata_checksum_correct;
    bool            ipv4_checksum_correct;
    bit<16>         L4_partial_complement_sum;
    
    nf_port_t   nf_port_hdr;

    /* ingress.get_transition_type -> ingress */
    bit<3>          transition_type;    // 0:in->out/nf, 1:out->in/nf, 2:nf->out, 3:nf->in, 4:in->nf, 5:out->nf, 6:update, 7:drop
    index_t         reverse_index;  

    /* ingress */
    bool            ingress_end;

    index_t         index_hi;
    bit<8>          index_lo_mask;
    bit<8>          timeout_byte;

    // packet info
    ipv4_flow_id_t  id;          
    time_t          time;
    // register

    bit             match;
    version_t       version_diff;
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

parser ParserI(packet_in packet,
               out headers hdr,
               out metadata meta,
               out ingress_intrinsic_metadata_t ig_intr_md) {

    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) metadata_csum;
    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_csum;
    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) L4_csum;

    state start {
        packet.extract(ig_intr_md);
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

        transition select(hdr.ethernet.ether_type) {//没检查MAC addr，没必要
            TYPE_METADATA   :   parse_metadata;
            TYPE_IPV4       :   parse_ipv4_with_transition_type;
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata);
        metadata_csum.add(hdr.metadata);
        meta.metadata_checksum_correct = metadata_csum.verify();
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
            LAN_ADDR &&& LAN_ADDR_MASK  :   reject_parse_sin;
            default                     :   mark_type_0;
        }
    }

    state reject_parse_sin {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        transition select(ip.dst_addr) {
            0 : accept;// this will never match
        }
    }

    state parse_sout {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        transition select(ip.dst_addr) {
            NAT_ADDR    :   mark_type_1;
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
        // The result is complement sum of all fields except src_port & dst_port. (Of course, "checksum" is not in "all")
        L4_csum.subtract({hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.checksum});
        meta.L4_partial_complement_sum = L4_csum.get();
        meta.is_tcp = true;

        // fill id
        meta.id.src_port = hdr.tcp.src_port;
        meta.id.dst_port = hdr.tcp.dst_port;

        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        L4_csum.subtract({hdr.udp.src_port, hdr.udp.dst_port, hdr.udp.checksum});
        meta.L4_partial_complement_sum = L4_csum.get();
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

control get_reverse_index(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md) {

    Register<bit<16>, bit<16>>(1) help1;
    Register<bit<16>, bit<16>>(1) help2;
    Register<bit<16>, bit<16>>(1) help3;// 所有RegisterAction共享SALU，一个Register只有一个SALU

    RegisterAction<bit<16>, bit<16>, bit<3>>(help1) reg_check_tcp_eport = {
        void apply(inout bit<16> reg, out bit<3> ret) {
            if(PORT_MIN <= hdr.tcp.dst_port && hdr.tcp.dst_port <= PORT_MAX)
                ret = 7;// drop
            else 
                ret = 0;
        }
    };
    RegisterAction<bit<16>, bit<16>, bit<3>>(help2) reg_check_udp_eport = {
        void apply(inout bit<16> reg, out bit<3> ret) {
            if(PORT_MIN <= hdr.udp.dst_port && hdr.udp.dst_port <= PORT_MAX)
                ret = 7;
            else 
                ret = 0;
        }
    };
    RegisterAction<bit<16>, bit<16>, bit<3>>(help3) reg_check_update_eport = {
        void apply(inout bit<16> reg, out bit<3> ret) {
            if(PORT_MIN <= hdr.metadata.switch_port && hdr.metadata.switch_port <= PORT_MAX)
                ret = 7;
            else 
                ret = 0;
        }
    };

    action check_tcp_eport() {
        bit<3>tmp = reg_check_tcp_eport.execute(0);
        meta.transition_type = meta.transition_type | tmp;
        meta.ingress_end = (bool)tmp[0:0];
    }

    action check_udp_eport() {
        bit<3>tmp = reg_check_udp_eport.execute(0);
        meta.transition_type = meta.transition_type | tmp;
        meta.ingress_end = (bool)tmp[0:0];
    }

    action check_update_eport() {
        bit<3>tmp = reg_check_update_eport.execute(0);
        meta.transition_type = meta.transition_type | tmp;
        meta.ingress_end = (bool)tmp[0:0];
    }

    apply {
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
        else if(meta.transition_type == 6) {
            check_update_eport();
            meta.reverse_index = hdr.metadata.switch_port - PORT_MIN;
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

    action ipv4_forward(bit<9> port, mac_addr_t smac, mac_addr_t dmac) {
        ig_intr_tm_md.ucast_egress_port = port;
        hdr.ethernet.src_addr = smac;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ip2port_mac{
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
        if(hdr.udp.isValid() && hdr.udp.checksum != 0) 
            meta.update_udp_checksum = true;
        else
            meta.update_udp_checksum = false;

        meta.L4_partial_complement_sum = ~meta.L4_partial_complement_sum;

        if((meta.transition_type & 4) == 0) {// 0, 1, 2, 3
            hdr.metadata.setInvalid();
            hdr.ethernet.ether_type = TYPE_IPV4;

            ip2port_mac.apply();
            //port2smac.apply();
        }
        else if((meta.transition_type & 6) == 4){// 4, 5
            
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
            hdr.metadata.nf_time = 0;
            hdr.metadata.checksum = 0;
            
            ig_intr_tm_md.ucast_egress_port = meta.nf_port_hdr.nf_port;
            
            if(meta.transition_type == 4) {
                //hdr.metadata.switch_port = meta.reg_map.eport;
                //hdr.metadata.version

                if(meta.timeout_byte == 0) 
                    hdr.metadata.type = 8w0b010_00000;
                else 
                    hdr.metadata.type = 8w0b011_00000;
                
                //hdr.metadata.index
            }
            else if(meta.transition_type == 5){
                hdr.metadata.switch_port = 0;
                hdr.metadata.version = 0;

                hdr.metadata.type = 8w0b100_00000;

                hdr.metadata.index = 0;
            }
        }
        else if(meta.transition_type == 6) {
            ig_intr_tm_md.ucast_egress_port = meta.nf_port_hdr.nf_port;
        }
        else if(meta.transition_type == 7) {
            drop();
        }
    }
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
    Register<time_t, index_t>((bit<32>)SWITCH_PORT_NUM, 0) primary_time;
    Register<bit<8>, index_t>((bit<32>)SWITCH_PORT_NUM >> 3, 0xff) timeout_history;// set all ports to state "timeout"

    Register<version_t, index_t>((bit<32>)SWITCH_PORT_NUM, 0) version;
    Register<index_t, index_t>((bit<32>)TOTAL_PORT_NUM, 0) reverse_map;

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
    RegisterAction<bit<32>, index_t, bit<32>>(map3) reg_map3_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.src_addr;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(map2) reg_map2_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.dst_addr;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(map1) reg_map1_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.src_port ++ hdr.metadata.dst_port;
        }
    };
    RegisterAction<bit<32>, index_t, bit<32>>(map0) reg_map0_write = {
        void apply(inout bit<32> reg) {
            reg = hdr.metadata.protocol ++ 8w0 ++ hdr.metadata.switch_port;
        }
    };

    //分成两个，一个是time，只有更不更新两种选择，另一个是history，记录是否曾timeout，BINGO~
    RegisterAction<time_t, index_t, bit<8>>(primary_time) reg_update_time = {
        void apply(inout time_t reg_time, out bit<8> ret) {
            if(meta.time - reg_time > AGING_TIME_US) 
                ret = ~8w0;
            else 
                ret = 8w0;

            if(meta.match == 1)
                reg_time = meta.time;
        }
    };

    RegisterAction<bit<8>, index_t, bit<8>>(timeout_history) reg_update_timeout_history = {
        void apply(inout bit<8> reg_timeout_history, out bit<8> ret) {
            if(meta.timeout_byte == 0xff){// clear
#define BUG
#ifdef BUG
                reg_timeout_history = meta.index_lo_mask | ~reg_timeout_history;
#else 
                reg_timeout_history = (~meta.index_lo_mask) & reg_timeout_history;//这个编译出来有问题啊，应该是andca，怎么会是orca呢
#endif
            }
            else {// meta.timeout_byte has 1 bit of 1, or meta.timeout_byte == 0
                reg_timeout_history = meta.timeout_byte | reg_timeout_history;
            }
            if(meta.timeout_byte == 0)
                ret = meta.index_lo_mask & reg_timeout_history;//zero, or non-zero
            else 
                ret = 0xff;

                // it will also return meta.index_lo_mask when meta.timeout_byte == 0xff, however it's OK.
        }
    };

    RegisterAction<version_t, index_t, version_t>(version) reg_read_version = {
        void apply(inout version_t reg_version, out version_t ret) {
            ret = reg_version;
        }
    };

    RegisterAction<version_t, index_t, version_t>(version) reg_update_version = {
        void apply(inout version_t reg_version, out version_t ret) {
            ret = hdr.metadata.version - reg_version;
            if(hdr.metadata.version - reg_version == 1) {
                reg_version = hdr.metadata.version;
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
            //if(meta.version_diff == 1) 
            reg_index = hdr.metadata.index;
        }
    };

    action map3_read(in index_t index) {
        hdr.metadata.src_addr = reg_map3_read.execute(index);
    }

    action map2_read(in index_t index) {
        hdr.metadata.dst_addr = reg_map2_read.execute(index);
    }

    action map1_read(in index_t index) {
        bit<32>tmp = reg_map1_read.execute(index);
        hdr.metadata.src_port = tmp[31:16];
        hdr.metadata.dst_port = tmp[15:0];
    }

    action map0_read(in index_t index) {
        bit<32>tmp = reg_map0_read.execute(index);
        hdr.metadata.protocol = tmp[31:24];
        hdr.metadata.zero = tmp[23:16];
        hdr.metadata.switch_port = tmp[15:0];
    }

    action map3_write(in index_t index) {
        reg_map3_write.execute(index);
    }

    action map2_write(in index_t index) {
        reg_map2_write.execute(index);
    }

    action map1_write(in index_t index) {
        reg_map1_write.execute(index);
    }

    action map0_write(in index_t index) {
        reg_map0_write.execute(index);
    }

    action update_time_mark_overwrite(in index_t index) {
        reg_update_time.execute(index);
        meta.timeout_byte = 0xff;
    }

    action update_time_mark_timeout(in index_t index, in bit<8> mask) {
        meta.timeout_byte = mask & reg_update_time.execute(index);
    }

    action update_timeout_history(in index_t index, in bit<8> mask) {
        meta.timeout_byte = mask & reg_update_timeout_history.execute(index);
    }

    action get_index_and_read_version() {
        ipv4_flow_id_t id = meta.id;
        bit<16>index = hashmap.get({id.src_addr, id.dst_addr, id.src_port, id.dst_port, id.protocol, id.zero}, 
                                (index_t)0, (index_t)SWITCH_PORT_NUM);
        hdr.metadata.index = index;                
        hdr.metadata.version = reg_read_version.execute(index);
    }

    action update_version(in index_t index) {
        meta.version_diff = reg_update_version.execute(index);
    }

    action reverse_map_read(in index_t index) {
        hdr.metadata.index = reg_reverse_map_read.execute(index);
    }

    action reverse_map_write(in index_t index) {
        reg_reverse_map_write.execute(index);
    }

    action get_time() {
        meta.time = ig_intr_md.ingress_mac_tstamp[41:10];// truncate
    }    
    
    apply {
        // bypass_egress
        ig_intr_tm_md.bypass_egress = true;

        // 检查parse和checksum
        if(ig_intr_prsr_md.parser_err != 0 ||                               // parse error
            (hdr.metadata.isValid() && !meta.metadata_checksum_correct) ||  // metadata checksum error
            (hdr.ipv4.isValid() && !meta.ipv4_checksum_correct)) {          // ipv4 checksum error
            meta.transition_type = 7;
            meta.ingress_end = true;
        }
        else {
            // 检查反向流的eport合法性
            get_reverse_index.apply(hdr, meta, ig_intr_md);
            //meta.ingress_end = false;// 这是唯一一个false赋值，用于初始化
        }
        /*
        if(meta.ingress_end) {
            ig_intr_dprs_md.drop_ctl = 1;
        }
        else {*/
            
            //if(ig_intr_prsr_md.parser_err != 0) {
                bit<48> tmp = hdr.ethernet.src_addr;
                hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
                hdr.ethernet.dst_addr = tmp;
            //}

            ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        //}

        /*
        // 检查反向流的eport合法性，顺便做一些初始化，同时读写version
        if(meta.ingress_end == false) {
            if(meta.transition_type == 7) {//这里是因为get_transition_type里没有对ingress_end赋值
                meta.ingress_end = true;
            }
            else if((meta.transition_type & 0b110) == 2) {// 2/3 直接结束
                meta.ingress_end = true;
            }
            else if(meta.transition_type == 0) {// 0/1，让所有包都有hdr.metadata
                hdr.metadata.setValid();

                get_index_and_read_version();// 0的index在这里获得
            }
            else if(meta.transition_type == 1) {
                hdr.metadata.setValid();
            }
            else if(meta.transition_type == 6) {
                update_version(hdr.metadata.index);
            }
        }
        
        get_time();

        /// Packet with type 2,3 ends here 
        /// In the following statements, only packet with type 0/1/6 can enter an "if" 

        // register "reverse_map"
        if(meta.ingress_end == false) {
            if (meta.transition_type == 1) {
                reverse_map_read(meta.reverse_index);// 1的index在这里获得
            }
            else if(meta.transition_type == 6) {
                if(meta.version_diff == 1) {
                    reverse_map_write(meta.reverse_index);
                }

                if(meta.version_diff == 0) {
                    meta.ingress_end = true;   
                }
                else if(meta.version_diff != 1){
                    meta.transition_type = 7;
                    meta.ingress_end = true;
                }   
            }
        }

        // register "map"
        // RegisterAction会两两合并
        if(meta.ingress_end == false) {
            if ((meta.transition_type & 0b110) == 0) {//type 0/1
                map3_read(hdr.metadata.index);
                map2_read(hdr.metadata.index);
                map1_read(hdr.metadata.index);
                map0_read(hdr.metadata.index);
            }
            else {// it must be type 6
                map3_write(hdr.metadata.index);
                map2_write(hdr.metadata.index);
                map1_write(hdr.metadata.index);
                map0_write(hdr.metadata.index);
            }
            // for type 0/1/6
            meta.index_hi = hdr.metadata.index >> 3;
            if((hdr.metadata.index & 7) == 0) meta.index_lo_mask = 0b0000_0001;
            else if((hdr.metadata.index & 7) == 1) meta.index_lo_mask = 0b0000_0010;
            else if((hdr.metadata.index & 7) == 2) meta.index_lo_mask = 0b0000_0100;
            else if((hdr.metadata.index & 7) == 3) meta.index_lo_mask = 0b0000_1000;
            else if((hdr.metadata.index & 7) == 4) meta.index_lo_mask = 0b0001_0000;
            else if((hdr.metadata.index & 7) == 5) meta.index_lo_mask = 0b0010_0000;
            else if((hdr.metadata.index & 7) == 6) meta.index_lo_mask = 0b0100_0000;
            else if((hdr.metadata.index & 7) == 7) meta.index_lo_mask = 0b1000_0000;
        }
        
        // matching
        
        if(meta.ingress_end == false) {

            if (meta.transition_type == 0) {

                if(hdr.metadata.src_addr == meta.id.src_addr) 
                    meta.tmp_bool3 = true;
                else   
                    meta.tmp_bool3 = false;

                if(hdr.metadata.dst_addr == meta.id.dst_addr)
                    meta.tmp_bool2 = true;
                else   
                    meta.tmp_bool2 = false;
                
                if(hdr.metadata.src_port == meta.id.src_port)
                    meta.tmp_bool1 = true;
                else   
                    meta.tmp_bool1 = false;
                
                if(hdr.metadata.dst_port == meta.id.dst_port && hdr.metadata.protocol == meta.id.protocol)
                    meta.tmp_bool0 = true;
                else   
                    meta.tmp_bool0 = false;
            }
            else if (meta.transition_type == 1) {
                if(hdr.metadata.dst_addr == meta.id.src_addr)
                    meta.tmp_bool2 = true;
                else   
                    meta.tmp_bool2 = false;

                if(hdr.metadata.dst_port == meta.id.src_port && hdr.metadata.protocol == meta.id.protocol) 
                    meta.tmp_bool1 = true;
                else 
                    meta.tmp_bool1 = false;

                if(hdr.metadata.switch_port == meta.id.dst_port)
                    meta.tmp_bool0 = true;
                else 
                    meta.tmp_bool0 = false;
            }
        }   
        
            
        // 综合match的结果
        if(meta.ingress_end == false) {
            if (meta.transition_type == 0) {
                if(meta.tmp_bool3 && meta.tmp_bool2 && meta.tmp_bool1 && meta.tmp_bool0) {
                    meta.match = 1;
                }
                else {
                    meta.match = 0;
                }
            }
            else if (meta.transition_type == 1) {
                if(!meta.tmp_bool0) {
                    // eport is not keep by switch
                    meta.transition_type = 5;
                    meta.ingress_end = true;
                }
                else if(meta.tmp_bool2 && meta.tmp_bool1) {
                    meta.match = 1;
                }
                else {
                    // eport is keep by switch but id mismatch
                    meta.transition_type = 7;
                    meta.ingress_end = true;
                }    
            }
            else {// it must be type 6
                meta.match = 1;
            }
        }

        /// packet with type 5 ends here 

        // register "time"
        if(meta.ingress_end == false) {// for type 0/1/6
            if(meta.transition_type == 6) {
                update_time_mark_overwrite(hdr.metadata.index);
            }
            else {
                update_time_mark_timeout(hdr.metadata.index, meta.index_lo_mask);
            }
        }

        // register "timeout_history"
        if(meta.ingress_end == false) {
            update_timeout_history(meta.index_hi, meta.index_lo_mask);

            if (meta.transition_type == 6) {
                meta.ingress_end = true;
            }
        }

        /// packet with type 6 ends here 
        
        
        
        // translate
        if(meta.ingress_end == false) {
            if (meta.transition_type == 0) {
                if(meta.match == 1 && meta.timeout_byte == 0) {
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
                if(meta.timeout_byte == 0) {// mata.match is always true
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

        send_out.apply(hdr, meta, ig_intr_dprs_md, ig_intr_tm_md);
        */
        
        
            

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
                send_to_NF();
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

            send_to_NF();
        }
        
        
        meta.update_metadata = hdr.metadata.isValid();
        meta.update_ip = hdr.ipv4.isValid();
        meta.update_tcp = hdr.tcp.isValid();
        meta.update_udp = hdr.udp.isValid() && (hdr.udp.checksum != 0);

        if(ig_intr_tm_md.ucast_egress_port != NF_PORT) {
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
                hdr.metadata.nf_time}
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

parser ParserE(packet_in packet,
               out headers hdr,
               out metadata meta,
               out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        //packet.extract(eg_intr_md);//这一句和bypass_egress必有其一，否则包会被丢
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
