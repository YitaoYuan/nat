/* -*- P4_16 -*- */
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
typedef bit<8> counter_t;
typedef bit<16> checksum_t;
typedef bit<SHARED_SWITCH_REG_NUM_LOG> index_hi_t;
typedef bit<16> lb_hash_t;

const bit<8>  TCP_PROTOCOL = 0x06;
const bit<8>  UDP_PROTOCOL = 0x11;

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_METADATA = SHARED_TYPE_METADATA;

const flow_num_t SWITCH_FLOW_NUM = SHARED_SWITCH_FLOW_NUM;
const flow_num_t SWITCH_FLOW_NUM_PER_REG = SHARED_SWITCH_FLOW_NUM_PER_REG;

const time_t AGING_TIME = SHARED_AGING_TIME_FOR_SWITCH;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>   ether_type;
}

header metadata_t {//32
    ip4_addr_t  src_addr;
    ip4_addr_t  dst_addr;
    port_t      src_port;
    port_t      dst_port;
    bit<8>      protocol;
    bit<8>      zero1;
    
    bit<32>     counter;

    version_t   old_version;
    version_t   new_version;
    bit<8>      type;
    counter_t   main_flow_count;
    
    flow_num_t  index;
    checksum_t  checksum;
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

struct ipv4_flow_id_t {
    ip4_addr_t   src_addr;
    ip4_addr_t   dst_addr;
    port_t      src_port;
    port_t      dst_port;
    bit<8>      protocol;
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
    metadata_t          metadata;
    ipv4_t              ipv4;
    tcp_t               tcp;
    udp_t               udp;
}

struct nf_port_t{
    bit<2>  port_type; 
    bit<14> unused;
}

struct ingress_metadata {
    /* parser -> ingress */
    bool            metadata_checksum_err;
    nf_port_t       nf_port_hdr;
    time_t          time;
    bit<4>          transition_type;    // 0:in->out/nf, 1:out->in/nf, 2:nf->out, 3:nf->in, 4:in->nf, 5:out->nf, 6:update, 7:drop

    /* ingress */
    bit<1>          all_flow_timeout;

    bit<32>         src_dst_port;

    index_hi_t      index_hi;
    flow_num_t      index_lo;

    ipv4_flow_id_t  id;
    ipv4_flow_id_t  cmp;
    
    bit<1>          update_key;
    bit<1>          update_val;

    version_t       version;
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

        meta.time = ig_intr_md.ingress_mac_tstamp[SHARED_TIME_OFFSET+15:SHARED_TIME_OFFSET];// truncate
        
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
            TYPE_IPV4 ++ 2w0:   mark_type_0;
            TYPE_IPV4 ++ 2w1:   mark_type_1;
            //default         :   parse_other_flow;
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata);
        metadata_csum.add(hdr.metadata);
        meta.metadata_checksum_err = metadata_csum.verify();
        transition select(hdr.metadata.type) {
            2:   mark_type_2;
            3:   mark_type_3;
            6:   mark_type_6;
        }
    }

    state mark_type_2 {
        meta.transition_type = 2;
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state mark_type_3 {
        meta.transition_type = 3;
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state mark_type_6 {
        meta.transition_type = 6;
        transition accept;
    }

    state mark_type_0 {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        meta.transition_type = 0;
        hdr.metadata.type = 0;
        transition select(ip.protocol ++ ip.ihl) {
            TCP_PROTOCOL ++ 4w5 :   initialize_metadata;
            UDP_PROTOCOL ++ 4w5 :   initialize_metadata;
            //default             :   parse_other_flow;
        }
    }

    state mark_type_1 {
        ipv4_t ip = packet.lookahead<ipv4_t>();
        meta.transition_type = 1;
        hdr.metadata.type = 1;
        transition select(ip.protocol ++ ip.ihl) {
            TCP_PROTOCOL ++ 4w5 :   initialize_metadata;
            UDP_PROTOCOL ++ 4w5 :   initialize_metadata;
            //default             :   parse_other_flow;
        }
    }

    state initialize_metadata{
        hdr.metadata.setValid();
        meta.metadata_checksum_err = false;
        
        hdr.metadata.index = 0x1;//这个是为了在pipe内赋hash值时只赋值一部分
        
        hdr.metadata.zero1 = 0xff;
        hdr.metadata.counter = 0xffffffff;
        hdr.metadata.old_version = 0xff;
        hdr.metadata.new_version = 0xff;
        hdr.metadata.main_flow_count = 0xff;
        hdr.metadata.checksum = 0xffff;

        L3L4_t l3l4 = packet.lookahead<L3L4_t>();
        hdr.metadata.src_addr = l3l4.src_addr;
        hdr.metadata.dst_addr = l3l4.dst_addr;
        hdr.metadata.protocol = l3l4.protocol;
        hdr.metadata.src_port = l3l4.src_port;
        hdr.metadata.dst_port = l3l4.dst_port;

        meta.id.src_addr = l3l4.src_addr;
        meta.id.dst_addr = l3l4.dst_addr;
        meta.id.src_port = l3l4.src_port;
        meta.id.dst_port = l3l4.dst_port;
        meta.id.protocol = l3l4.protocol;

        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);   
        transition accept;
    }

    /*state parse_other_flow {
        meta.metadata_checksum_err = false;
        meta.transition_type = 8;
        transition accept;
    }*/
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

    action set_egress_port(bit<9> port) {
        ig_intr_dprs_md.drop_ctl = 0;//这个drop_ctl=0一定不能省略，不知道为什么，明明文档说初始化为0的
        ig_intr_tm_md.ucast_egress_port = port;
    }

    table forward_table {
        key = {
            meta.transition_type: ternary;
            meta.update_val: ternary;
            hdr.ipv4.dst_addr: ternary;// for type 1
        }
        actions = {
            set_egress_port;
            drop;
        }
        size = 64;
        default_action = drop();
    }

    apply {
        forward_table.apply();

        hdr.ethernet.ether_type = TYPE_METADATA;

        if(meta.update_val == 0) {
            if(meta.transition_type == 0)
                hdr.metadata.type = 4;
            else if(meta.transition_type == 1)
                hdr.metadata.type = 5;
        }
    }
}

control Key(
        inout headers hdr,
        inout ingress_metadata meta
        ) {
    Register<bit<32>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) key3;
    Register<bit<32>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) key2;
    Register<bit<32>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) key1;
    Register<bit<8>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) key0;

    RegisterAction<bit<32>, flow_num_t, bit<32>>(key3) reg_key3_rw = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            if(meta.update_key == 1) {
                reg = hdr.metadata.src_addr;
            }
            ret = reg;
        }
    };
    RegisterAction<bit<32>, flow_num_t, bit<32>>(key2) reg_key2_rw = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            if(meta.update_key == 1) {
                reg = hdr.metadata.dst_addr;
            }
            ret = reg;
        }
    };
    RegisterAction<bit<32>, flow_num_t, bit<32>>(key1) reg_key1_rw = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            if(meta.update_key == 1) {
                reg = meta.src_dst_port;
            }
            ret = reg;
        }
    };
    RegisterAction<bit<8>, flow_num_t, bit<8>>(key0) reg_key0_rw = {
        void apply(inout bit<8> reg, out bit<8> ret) {
            if(meta.update_key == 1) {
                reg = hdr.metadata.protocol;
            }
            ret = reg;
        }
    };

    action key3_rw(in flow_num_t index) {
        hdr.metadata.src_addr = reg_key3_rw.execute(index);
    }

    action key2_rw(in flow_num_t index) {
        hdr.metadata.dst_addr = reg_key2_rw.execute(index);
    } 

    action key1_rw(in flow_num_t index) {
        bit<32>src_dst_port = reg_key1_rw.execute(index);
        hdr.metadata.src_port = src_dst_port[31:16];
        hdr.metadata.dst_port = src_dst_port[15:0];
    } 

    action key0_rw(in flow_num_t index) {
        hdr.metadata.protocol = reg_key0_rw.execute(index);
    } 

    apply {
        key3_rw(meta.index_lo);
        key2_rw(meta.index_lo);
        key1_rw(meta.index_lo);
        key0_rw(meta.index_lo);
    }
}
control Val(
        inout headers hdr,
        inout ingress_metadata meta
        ) {
    Register<bit<32>, flow_num_t>((bit<32>)SWITCH_FLOW_NUM_PER_REG, 0) val1;

    RegisterAction<bit<32>, flow_num_t, bit<32>>(val1) reg_val1_rw = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            if(meta.update_key == 1 && meta.update_val == 1) {
                reg = 1;
            }
            else if(meta.update_val == 1) {
                reg = reg + 1;
            }
            ret = reg;
        }
    };

    action val1_rw(in flow_num_t index) {
        hdr.metadata.counter = reg_val1_rw.execute(index);
    } 
    apply{
        val1_rw(meta.index_lo);
    }
}

control Ingress(
        inout headers hdr,
        inout ingress_metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    CRCPolynomial<bit<32>>((bit<32>)SHARED_SWITCH_CRC_POLY, false, false, false, 32w0, 32w0) polynomial;
    Hash<bit<SHARED_SWITCH_FLOW_NUM_LOG>>(HashAlgorithm_t.CUSTOM, polynomial) hashmap0;
    Hash<bit<SHARED_SWITCH_FLOW_NUM_LOG>>(HashAlgorithm_t.CUSTOM, polynomial) hashmap1;

    Register<version_t, flow_num_t>((bit<32>)SWITCH_FLOW_NUM, 0) version;

    // MAX_SIZE = 286720
    Register<time_t, flow_num_t>((bit<32>)SWITCH_FLOW_NUM, 0xf000) all_flow_timestamp;
                                                        /* a negative number */
    Register<counter_t, flow_num_t>((bit<32>)SWITCH_FLOW_NUM, 0) main_flow_counter;

    RegisterAction<version_t, flow_num_t, version_t>(version) reg_version_read = {
        void apply(inout version_t reg_version, out version_t ret) {
            ret = reg_version;
        }
    };

    RegisterAction<version_t, flow_num_t, version_t>(version) reg_version_update = {
        void apply(inout version_t reg_version, out version_t ret) {
            ret = reg_version;
            if(reg_version == hdr.metadata.old_version) {
                reg_version = hdr.metadata.new_version;
            }
        }
    };

    RegisterAction<version_t, flow_num_t, void>(version) reg_version_inplace_update = {
        void apply(inout version_t reg_version) {
            reg_version = reg_version + 16;
        }
    };

    RegisterAction<time_t, flow_num_t, bit<1>>(all_flow_timestamp) reg_forward_update_all_flow_timestamp = {
        void apply(inout time_t reg_time, out bit<1> ret) {
            if(meta.time - reg_time > AGING_TIME || meta.time - reg_time < 0) {
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
            if(meta.time - reg_time > AGING_TIME || meta.time - reg_time < 0) {
                ret = 1;
            }
            else {
                ret = 0;
                reg_time = meta.time;
            }
        }
    };

    RegisterAction<counter_t, flow_num_t, counter_t>(main_flow_counter) reg_main_flow_counter_update = {
        void apply(inout counter_t reg_cnt, out counter_t ret) {
            reg_cnt = reg_cnt + 1;
            ret = reg_cnt;
        }
    };

    RegisterAction<counter_t, flow_num_t, counter_t>(main_flow_counter) reg_main_flow_counter_read = {
        void apply(inout counter_t reg_cnt, out counter_t ret) {
            ret = reg_cnt;
        }
    };

    Key() k0;
    Key() k1;
    Val() v0;
    Val() v1;

    apply {
        // stage 0
        meta.src_dst_port = hdr.metadata.src_port ++ hdr.metadata.dst_port;

        if((meta.transition_type & 0b1110) == 0) {// 0/1
            hdr.metadata.zero1 = 0;
            hdr.metadata.new_version = 0;
        }


        if(meta.transition_type == 0) {
#ifdef ONE_ENTRY_TEST
            hdr.metadata.index = 1;
#else 
            ipv4_flow_id_t id = meta.id;
            hdr.metadata.index[SHARED_SWITCH_FLOW_NUM_LOG-1:0] = hashmap0.get({id.src_addr, id.dst_addr, id.src_port, id.dst_port, id.protocol, 8w0});
#endif
        }
        else if(meta.transition_type == 1) {
#ifdef ONE_ENTRY_TEST
            hdr.metadata.index = 1;
#else
            ipv4_flow_id_t id = meta.id;
            hdr.metadata.index[SHARED_SWITCH_FLOW_NUM_LOG-1:0] = hashmap1.get({id.dst_addr, id.src_addr, id.dst_port, id.src_port, id.protocol, 8w0});
#endif
        }

        // 检查parse和checksum
        if(ig_intr_prsr_md.parser_err != PARSER_ERROR_OK || meta.metadata_checksum_err) {  // metadata checksum error
            //meta.transition_type = 7;
            ig_intr_dprs_md.drop_ctl = 0x1;
            //ig_intr_dprs_md.drop_ctl = 0;
            //ig_intr_tm_md.ucast_egress_port = 180;
            return;
        }

        // stage 1

        meta.index_lo = hdr.metadata.index & (SWITCH_FLOW_NUM_PER_REG - 1);
        meta.index_hi = hdr.metadata.index[SHARED_SWITCH_FLOW_NUM_LOG-1:SHARED_SWITCH_FLOW_NUM_PER_REG_LOG];
        
        if(meta.transition_type == 0 || meta.transition_type == 6) {
            meta.all_flow_timeout = reg_forward_update_all_flow_timestamp.execute(hdr.metadata.index);
        }
        else if(meta.transition_type == 1) {// 1
            meta.all_flow_timeout = reg_backward_update_all_flow_timestamp.execute(hdr.metadata.index);
        }

        // stage 2

        if(meta.transition_type == 0 && meta.all_flow_timeout == 1) {
            reg_version_inplace_update.execute(hdr.metadata.index);
        }
        else if(meta.transition_type == 6) {
            meta.version = reg_version_update.execute(hdr.metadata.index);
        }
        else if(meta.transition_type == 0 || meta.transition_type == 1){// (0, 0) or (1, _)
            hdr.metadata.old_version = reg_version_read.execute(hdr.metadata.index);
        }

        if(meta.transition_type == 6) {
            hdr.metadata.old_version = meta.version;
        }

        meta.update_key = 0;
        meta.update_val = 1;
    
        if ((meta.transition_type == 0 && meta.all_flow_timeout == 1) || 
            (meta.transition_type == 6 && meta.version == hdr.metadata.old_version)) {
            meta.update_key = 1;
        }
        if(meta.transition_type == 6 &&
            (hdr.metadata.main_flow_count == 1 || meta.version != hdr.metadata.old_version)) {// closing or version mismatch
                // this is a intermediate state during replacement, don't change value
                meta.update_val = 0;
        }

        // for 0/1/2/3/6, (6 must match the version)
        if(meta.index_hi == 0) k0.apply(hdr, meta);
        else k1.apply(hdr, meta);
        //else if(meta.index_hi == 2) kv2.apply(hdr, meta);
        //else if(meta.index_hi == 3) kv3.apply(hdr, meta);

        // for 0/1/2/3, do matching. (0 with inplace update is not included)
        if(meta.update_key == 0 && hdr.metadata.protocol != meta.id.protocol) {
            meta.update_val = 0;
        }

        if(meta.transition_type == 0) {
            meta.cmp.src_addr = hdr.metadata.src_addr;
            meta.cmp.dst_addr = hdr.metadata.dst_addr;
            meta.cmp.src_port = hdr.metadata.src_port;
            meta.cmp.dst_port = hdr.metadata.dst_port;
        }
        else {
            meta.cmp.src_addr = hdr.metadata.dst_addr;
            meta.cmp.dst_addr = hdr.metadata.src_addr;
            meta.cmp.src_port = hdr.metadata.dst_port;
            meta.cmp.dst_port = hdr.metadata.src_port;
        } 

        if(meta.update_key == 0) {
            if(meta.cmp.src_addr != meta.id.src_addr)
                meta.update_val = 0;
            else if(meta.cmp.dst_addr != meta.id.dst_addr)
                meta.update_val = 0;
            else if(meta.cmp.src_port != meta.id.src_port || meta.cmp.dst_port != meta.id.dst_port)
                meta.update_val = 0;
        }

        // for 0/1/2/3/6, (6 must match the version)
        if(meta.index_hi == 0) v0.apply(hdr, meta);
        else v1.apply(hdr, meta);
        //else if(meta.index_hi == 2) kv2.apply(hdr, meta);
        //else if(meta.index_hi == 3) kv3.apply(hdr, meta);
        
        // register main_flow_time
        if(meta.transition_type != 6) {// for type 0/1/2/3
            if(meta.update_val == 1) {
                hdr.metadata.main_flow_count = reg_main_flow_counter_update.execute(hdr.metadata.index);
            }
            else {
                hdr.metadata.main_flow_count = reg_main_flow_counter_read.execute(hdr.metadata.index);
            }
        }

        send_out.apply(hdr, meta, ig_intr_md, ig_intr_dprs_md, ig_intr_tm_md);
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
        transition select(hdr.ethernet.ether_type) {
            TYPE_METADATA   :   parse_metadata;
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata);
        meta.transition_type = hdr.metadata.type[3:0];
        transition select(meta.transition_type) {
            6 : accept;
            default : parse_ipv4;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        L4_csum.subtract({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});

        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL    :   parse_tcp;
            UDP_PROTOCOL    :   parse_udp;
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
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    action set_mac(mac_addr_t src_addr, mac_addr_t dst_addr) {
        hdr.ethernet.src_addr = src_addr;
        hdr.ethernet.dst_addr = dst_addr;
    }

    table mac_table {
        key = {
            meta.transition_type: ternary;
            hdr.ipv4.dst_addr: ternary;
        }
        actions = {
            set_mac;
        }
        size = 256;
        default_action = set_mac(48w0x0, 48w0xffffffffffff);
    }
    apply { 
        eg_intr_dprs_md.drop_ctl = 0;

        if(hdr.ethernet.ether_type != TYPE_METADATA) return;
        
        
        if(hdr.udp.isValid() && hdr.udp.checksum != 0) 
            meta.update_udp_checksum = true;
        else
            meta.update_udp_checksum = false;


        if((meta.transition_type & 0b1100) == 0) {//0, 1, 2
            hdr.metadata.setInvalid();
            hdr.ethernet.ether_type = TYPE_IPV4;
        }

        mac_table.apply();
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
                hdr.metadata.zero1,

                hdr.metadata.counter,

                hdr.metadata.old_version,
                hdr.metadata.new_version,
                hdr.metadata.type,
                hdr.metadata.main_flow_count,

                hdr.metadata.index
                }
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
                  in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md) {
            
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
