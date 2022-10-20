/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

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

struct nf_port_t{
    bit<9>  nf_port;
    bit<2>  port_type; 
    bit<5>  unused;
}

struct checksum_helper_t {
    ip4_addr_t  neg_src_addr;
    ip4_addr_t  neg_dst_addr;
    port_t      neg_src_port;
    port_t      neg_dst_port;
    bit<16>     neg_checksum;
}

struct metadata {
    /* parser -> ingress */
    bool            is_tcp;

    bool            metadata_checksum_err;
    //bit<16>         L4_partial_complement_sum;
    checksum_helper_t   checksum_helper;
    
    nf_port_t       nf_port_hdr;

    /* ingress.get_transition_type -> ingress */
    bit<4>          transition_type;    // 0:in->out/nf, 1:out->in/nf, 2:nf->out, 3:nf->in, 4:in->nf, 5:out->nf, 6:update, 7:drop
    index_t         reverse_index;  
    //bool            mac_match;

    /* ingress */
    bool            ingress_end;

    index_t         index_hi;
    bit<8>          index_lo_mask;
    bit<8>          inv_index_lo_mask;
    bit<8>          timeout_byte;

    // packet info
    ipv4_flow_id_t  id;          
    time_t          time;
    // register

    bit             match;
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

        meta.transition_type = 0;

        transition select(hdr.ethernet.ether_type) {//没检查MAC addr，没必要
            TYPE_IPV4:   parse_ipv4;
            default  :   parse_other_flow;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol ++ hdr.ipv4.ihl) {
            TCP_PROTOCOL ++ 4w5 : parse_tcp;
            UDP_PROTOCOL ++ 4w5 : parse_udp;
            default             : parse_other_flow;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);

        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);

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


control Ingress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    action drop() {
        ig_intr_dprs_md.drop_ctl = 0x1;
    }

    action ipv4_forward(bit<9> port, /*mac_addr_t smac, */mac_addr_t dmac) {
        ig_intr_tm_md.ucast_egress_port = port;
        //hdr.ethernet.src_addr = smac;
        hdr.ethernet.dst_addr = dmac;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        //如果在同一个L2网络下，减ttl会导致ping对方不回复
        //不在同一个L2网络下，则可以减
    }

    table ip2port_mac{
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 32;
        default_action = drop();
    }

    Register<bit<1>, index_t>((bit<32>)128, 0) map;
    RegisterAction<bit<1>, index_t, bit<1>>(map) reg_map_read = {
        void apply(inout bit<1> reg, out bit<1> ret) {
            ret = reg;
        }
    };

    RegisterAction<bit<1>, index_t, bit<1>>(map) reg_map_write = {
        void apply(inout bit<1> reg, out bit<1> ret) {
            //ret = reg;
            reg = 1;
        }
    };

    RegisterAction<bit<1>, index_t, bit<1>>(map) reg_map_clear = {
        void apply(inout bit<1> reg, out bit<1> ret) {
            //ret = reg;
            reg = 0;
        }
    };
    

    apply {
        // bypass_egress
        ig_intr_tm_md.bypass_egress = 1;
        ip2port_mac.apply();
        //hdr.ethernet.dst_addr = 0;
        //这个一删就不能work
        //现在的情况是smac和dmac赋值一删就能work，否则不work
        
        if(hdr.ethernet.ether_type == 0) {
            hdr.ethernet.ether_type = (bit<16>)reg_map_read.execute(0);
        }
        else if(hdr.ethernet.ether_type == 1){
            hdr.ethernet.ether_type = (bit<16>)reg_map_write.execute(64);
        }
        else {
            hdr.ethernet.ether_type = (bit<16>)reg_map_clear.execute(64);
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control IngressDeparser(
        packet_out packet,
        inout headers hdr,
        in metadata meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    apply{
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
