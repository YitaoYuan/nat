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
const ip4_addr_t LAN_ADDR_START = SHARED_LAN_ADDR_START;// 192.168.11.0
const ip4_addr_t LAN_ADDR_END = SHARED_LAN_ADDR_END;// not included
const ip4_addr_t NAT_ADDR = SHARED_NAT_ADDR;// 10.1.1.1

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

    bit         is_to_in;//最终会去往in
    bit         is_to_out;
    bit         is_update;
    bit<5>      zero2;

    

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

struct metadata {
    /* parser -> ingress */
    bool            parse_error;
    bool            verify_metadata;
    bool            verify_ip;
    bool            verify_tcp;
    bool            verify_udp;
    bool            is_tcp;
    bit<16>         L4_length;
    bit<4>          valid_bits;

    /* checksum -> ingress */
    bool            checksum_error;

    /* ingress */
    bool            control_ignore;
    bool            is_from_nfv;

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
    bool            apply_dst;

    /* ingress -> deparser */
    bool            update_metadata;
    bool            update_ip;
    bool            update_tcp;
    bool            update_udp;

    /* ingress checksum -> egress checksum */
    bit<16>         L4_checksum_partial;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserI(packet_in packet,
               out headers hdr,
               out metadata meta,
               out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4: parse_ipv4;
            TYPE_METADATA: parse_metadata;
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata);
        transition select(hdr.metadata.is_update) {
            1w0: parse_ipv4;
            1w1: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        bit chk = (bit)(hdr.ipv4.version == 4 && hdr.ipv4.ihl == 5);
        transition select(hdr.ipv4.protocol ++ chk) {
            TCP_PROTOCOL ++ 1w1: parse_tcp;
            UDP_PROTOCOL ++ 1w1: parse_udp;
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
}

control MyMetadataInit(inout headers hdr, inout metadata meta) {
    apply {
        meta.valid_bits = 0;
        if(hdr.ethernet.isValid()) meta.valid_bits[3:3] = 1;
        if(hdr.metadata.isValid()) meta.valid_bits[2:2] = 1;
        if(hdr.ipv4.isValid()) meta.valid_bits[1:1] = 1;
        if(hdr.tcp.isValid() || hdr.udp.isValid()) meta.valid_bits[0:0] = 1;
        
        /* 编译器有bug，不能像下面这样写
        meta.valid_bits = ( (bit)hdr.ethernet.isValid() ++
                            (bit)hdr.metadata.isValid() ++
                            (bit)hdr.ipv4.isValid() ++
                            (bit)(hdr.tcp.isValid()||hdr.udp.isValid()) );*/

        meta.parse_error = (meta.valid_bits != 4w0b1100) && (meta.valid_bits != 4w0b1111) && (meta.valid_bits != 4w0b1011) ? true : false;
        meta.verify_metadata = hdr.metadata.isValid() ? true : false;
        meta.verify_ip = hdr.ipv4.isValid() ? true : false;
        meta.verify_tcp = hdr.tcp.isValid() ? true : false;
        meta.verify_udp = (hdr.udp.isValid() ? true : false) && hdr.udp.checksum != 0;
        meta.is_tcp = hdr.tcp.isValid() ? true : false;
        if(hdr.ipv4.isValid()) meta.L4_length = hdr.ipv4.total_length - (bit<16>)hdr.ipv4.ihl * 4;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    
    //Checksum<bit<16>>(HashAlgorithm_t.CSUM16) csum16;

    apply {
        /*
        bit<16> checksum;
        meta.checksum_error = false;
        if(meta.verify_metadata) {
            checksum = csum16.update(
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
            if(checksum != hdr.metadata.checksum) {
                meta.checksum_error = true;
                return;
            }
        }
        
        if(meta.verify_ip) {
            checksum = csum16.update(
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
            if(checksum != hdr.ipv4.checksum) {
                meta.checksum_error = true;
                return;
            }
        }
        
        if(meta.verify_tcp) {
            checksum = csum16.update(
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
            meta.L4_checksum_partial = checksum;
        }
        
        if(meta.verify_udp) {
            checksum = csum16.update(
                {hdr.ipv4.src_addr, 
                hdr.ipv4.dst_addr,
                8w0,
                hdr.ipv4.protocol,
                meta.L4_length,

                hdr.udp.src_port,
                hdr.udp.dst_port,
                hdr.udp.unused}
            );
            meta.L4_checksum_partial = checksum;
        }
        */
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control IngressP(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

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

    Hash<index_t>(HashAlgorithm_t.CRC16) hashmap;
    
    Register<bit<32>, bit<32>>((bit<32>)SWITCH_PORT_NUM, 0) map3;
    Register<bit<32>, bit<32>>((bit<32>)SWITCH_PORT_NUM, 0) map2;
    Register<bit<32>, bit<32>>((bit<32>)SWITCH_PORT_NUM, 0) map1;
    Register<bit<32>, bit<32>>((bit<32>)SWITCH_PORT_NUM, 0) map0;
    // TODO：time后续可以改成8bit
    Register<time_t, bit<32>>((bit<32>)SWITCH_PORT_NUM, FOREVER_TIMEOUT) primary_time;
    Register<version_t, bit<32>>((bit<32>)SWITCH_PORT_NUM, 0) version;
    Register<index_t, bit<32>>(PORT_MAX - (bit<32>)PORT_MIN, 0) reverse_map;

    RegisterAction<bit<32>, bit<32>, bit<32>>(map3) reg_map3_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(map2) reg_map2_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(map1) reg_map1_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(map0) reg_map0_read = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(map3) reg_map3_swap = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
            reg = meta.reg_tmp3;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(map2) reg_map2_swap = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
            reg = meta.reg_tmp2;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(map1) reg_map1_swap = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
            reg = meta.reg_tmp1;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(map0) reg_map0_swap = {
        void apply(inout bit<32> reg, out bit<32> ret) {
            ret = reg;
            reg = meta.reg_tmp0;
        }
    };

    RegisterAction<time_t, bit<32>, bool>(primary_time) reg_update_time_on_match = {
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

    RegisterAction<time_t, bit<32>, bool>(primary_time) reg_update_time_on_mismatch = {
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

    RegisterAction<time_t, bit<32>, time_t>(primary_time) reg_write_time = {
        void apply(inout time_t reg_time) {
            reg_time = meta.time;
        }
    };

    RegisterAction<version_t, bit<32>, version_t>(version) reg_read_version = {
        void apply(inout version_t reg_version, out version_t ret) {
            ret = reg_version;
        }
    };

    RegisterAction<version_t, bit<32>, version_t>(version) reg_update_version = {
        void apply(inout version_t reg_version, out version_t ret) {
            version_t version_diff = meta.version - reg_version;
            ret = version_diff;
            if(version_diff == 1) {
                reg_version = meta.version;
            }
        }
    };

    RegisterAction<index_t, bit<32>, index_t>(reverse_map) reg_reverse_map_read = {
        void apply(inout index_t reg_index, out index_t ret) {
            ret = reg_index;
        }
    };

    RegisterAction<index_t, bit<32>, index_t>(reverse_map) reg_reverse_map_write = {
        void apply(inout index_t reg_index) {
            reg_index = meta.index;
        }
    };

    RegisterAction<index_t, bit<32>, index_t>(reverse_map) reg_reverse_map_clear = {
        void apply(inout index_t reg_index) {
            reg_index = 0;
        }
    };

    action map_read(index_t index) {
        meta.reg_tmp3 = reg_map3_read.execute((bit<32>)index);
        meta.reg_tmp2 = reg_map2_read.execute((bit<32>)index);
        meta.reg_tmp1 = reg_map1_read.execute((bit<32>)index);
        meta.reg_tmp0 = reg_map0_read.execute((bit<32>)index);
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

    action map_swap(index_t index) {
        meta.reg_tmp3 = meta.reg_map.id.src_addr;
        meta.reg_tmp2 = meta.reg_map.id.dst_addr;
        meta.reg_tmp1 = meta.reg_map.id.src_port ++ meta.reg_map.id.dst_port;
        meta.reg_tmp0 = meta.reg_map.id.protocol ++ meta.reg_map.id.zero ++ meta.reg_map.eport;

        meta.reg_tmp3 = reg_map3_swap.execute((bit<32>)index);
        meta.reg_tmp2 = reg_map2_swap.execute((bit<32>)index);
        meta.reg_tmp1 = reg_map1_swap.execute((bit<32>)index);
        meta.reg_tmp0 = reg_map0_swap.execute((bit<32>)index);
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

    action update_time_on_match(index_t index) {
        meta.timeout = reg_update_time_on_match.execute((bit<32>)index);
    }

    action update_time_on_mismatch(index_t index) {
        meta.timeout = reg_update_time_on_mismatch.execute((bit<32>)index);
    }

    action write_time(index_t index) {
        reg_write_time.execute((bit<32>)index);
    }

    action read_version(index_t index) {
        meta.version = reg_read_version.execute((bit<32>)index);
    }

    action update_version(index_t index) {
        meta.version_diff = reg_update_version.execute((bit<32>)index);
    }

    action reverse_map_read(index_t index) {
        meta.index = reg_reverse_map_read.execute((bit<32>)index);
    }

    action reverse_map_write(index_t index) {
        reg_reverse_map_write.execute((bit<32>)index);
    }

    action reverse_map_clear(index_t index) {
        reg_reverse_map_clear.execute((bit<32>)index);
    }

    action get_transition_type() {

        meta.control_ignore = false;

        if(ig_intr_md.ingress_port == NFV_PORT) {
            meta.is_from_nfv = true;

            if(meta.valid_bits != 4w0b1100 && meta.valid_bits != 4w0b1111) {
                meta.control_ignore = true;
                return;
            }

            if(hdr.ethernet.src_addr != NFV_INNER_MAC || 
                hdr.ethernet.dst_addr != SWITCH_INNER_MAC ||
                hdr.ethernet.ether_type != TYPE_METADATA) {// parser didn't check this
                meta.control_ignore = true;
                return;
            }
            if(hdr.metadata.zero1 != 0 || hdr.metadata.zero2 != 0) {
                meta.control_ignore = true;
                return;
            }
            if( (bit<2>)hdr.metadata.is_to_in +
                (bit<2>)hdr.metadata.is_to_out +
                (bit<2>)hdr.metadata.is_update != 1) {
                meta.control_ignore = true;
                return;
            } 
            bit<5> bits = meta.valid_bits ++ hdr.metadata.is_update;
            if(bits != 5w0b1100_1 && bits != 5w0b1111_0) {
                meta.control_ignore = true;
                return;
            }
        }
        else {
            if(meta.valid_bits != 4w0b1011) {
                meta.control_ignore = true;
                return;
            }
            meta.is_from_nfv = false;

            if(LAN_ADDR_START <= hdr.ipv4.src_addr && hdr.ipv4.src_addr < LAN_ADDR_END
                && !(LAN_ADDR_START <= hdr.ipv4.dst_addr && hdr.ipv4.dst_addr < LAN_ADDR_END)) {
                hdr.metadata.is_to_in = 0;
                hdr.metadata.is_to_out = 1;
            }
            else if(!(LAN_ADDR_START <= hdr.ipv4.src_addr && hdr.ipv4.src_addr < LAN_ADDR_END) 
                && hdr.ipv4.dst_addr == NAT_ADDR) {
                hdr.metadata.is_to_in = 1;
                hdr.metadata.is_to_out = 0;
            }
            else {
                meta.control_ignore = true;
                return;
            }
        }
    }

    action get_id() {
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

    action get_index() {
        ipv4_flow_id_t id = meta.id;
        meta.index = 1 + hashmap.get({id.src_addr, id.dst_addr, id.src_port, id.dst_port, id.protocol, id.zero}, 
                                (index_t)0, (index_t)SWITCH_PORT_NUM-1);
        // port PORT_MIN and index 0 is reserved
    }

    action get_time() {
        meta.time = 1w0 ++ (bit<31>)ig_intr_md.ingress_mac_tstamp;
        // 48->31->32
    }    
    /*
    action read_entry() {
        map_read(meta.entry, meta.index);

        meta.primary_timeout = meta.time - meta.entry.primary_time > AGING_TIME_US;
        meta.secondary_timeout = meta.time - meta.entry.secondary_time > AGING_TIME_US;
        meta.match = meta.entry.map.id == meta.id;
    }
    */
    action translate() {
        hdr.ipv4.src_addr = NAT_ADDR;
        if(meta.is_tcp) 
            hdr.tcp.src_port = meta.reg_map.eport;
        else
            hdr.udp.src_port = meta.reg_map.eport;
    }
    
    action reverse_translate() {
        hdr.ipv4.dst_addr = meta.reg_map.id.src_addr;
        if(meta.is_tcp)
            hdr.tcp.dst_port = meta.reg_map.id.src_port;
        else
            hdr.udp.dst_port = meta.reg_map.id.src_port;
    }

    action set_metadata(bool send_update) {
        hdr.ethernet.ether_type = TYPE_METADATA;

        // Why p4c for tofino does not support "struct in header" ???
        hdr.metadata.src_addr = meta.id.src_addr;
        hdr.metadata.dst_addr = meta.id.dst_addr;
        hdr.metadata.src_port = meta.id.src_port;
        hdr.metadata.dst_port = meta.id.dst_port;
        hdr.metadata.protocol = meta.id.protocol;
        hdr.metadata.zero1 = 0;

        hdr.metadata.switch_port = send_update ? meta.reg_map.eport : 0;
        
        //hdr.metadata.primary_map = meta.entry.map;
        //hdr.metadata.secondary_map = {meta.id, 0};
        
        //hdr.metadata.is_to_in
        //hdr.metadata.is_to_out
        hdr.metadata.is_update = send_update ? (bit)meta.timeout : 0;
        hdr.metadata.zero2 = 0;
        hdr.metadata.version = send_update ? meta.version : 0;
        hdr.metadata.index = send_update ? meta.index : 0;
        hdr.metadata.nfv_time = 0;
        hdr.metadata.checksum = 0;
    }

    action send_to_NFV() {
        ig_intr_tm_md.ucast_egress_port = 2;
        hdr.ethernet.src_addr = 48w1;
        hdr.ethernet.dst_addr = 48w2;
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
        /*
        ig_intr_tm_md.bypass_egress = true;

        MyMetadataInit.apply(hdr, meta);

        if(meta.parse_error || ig_intr_prsr_md.parser_err != 0) {
            drop();
            return;
        }

        MyVerifyChecksum.apply(hdr, meta);

        if(meta.checksum_error) {
            drop();
            return;
        }
        //if(hdr.ethernet.ether_type != TYPE_IPV4) {drop(); return;}
        // TODO
        // 还需要判断下DSTMAC是不是本地端口的MAC
        if(!hdr.metadata.isValid()) hdr.metadata.setValid();

        get_time();
        get_transition_type();

        if(meta.control_ignore) {
            drop();
            return;
        }

        meta.apply_dst = false;

        if(!meta.is_from_nfv && hdr.metadata.is_to_in == 1) {
            port_t eport = meta.is_tcp? hdr.tcp.dst_port : hdr.udp.dst_port;
            port_t src_port = meta.is_tcp? hdr.tcp.src_port : hdr.udp.src_port;
            ip4_addr_t src_addr = hdr.ipv4.src_addr;
            bit<8> protocol = hdr.ipv4.protocol;

            
            if(eport <= PORT_MIN || (bit<32>)eport >= PORT_MAX) {
                drop();
                return;
            }

            reverse_map_read(eport - PORT_MIN);// -> meta.index

            // 注意！！这里读出来的meta.index可能为0

            //assert(meta.index < SWITCH_PORT_NUM); //

            map_read(meta.index);//meta.index可能为0

            
            if(meta.index == 0 || meta.reg_map.eport != eport) {
                // eport is not keep by switch
                set_metadata(false);
                send_to_NFV();
            }
            else {
                ipv4_flow_id_t map_id = meta.reg_map.id;

                if({map_id.dst_addr, map_id.dst_port, map_id.protocol} != {src_addr, src_port, protocol}) {
                    // eport is keep by switch but id mismatch
                    drop();
                    return;
                }
                
                update_time_on_match(meta.index);
                if(meta.timeout) {
                    // aging
                    drop();
                    return;
                }

                reverse_translate();
                meta.apply_dst = true;
                //ip2port_dmac.apply();
            }
        }
        else if(!meta.is_from_nfv && hdr.metadata.is_to_out == 1) {
            get_id();
            get_index();

            //read_entry();
            
            map_read(meta.index);
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
        else if(meta.is_from_nfv && hdr.metadata.is_to_in == 1) {
            meta.apply_dst = true;
            //ip2port_dmac.apply();
        }
        else if(meta.is_from_nfv && hdr.metadata.is_to_out == 1) {
            meta.apply_dst = true;
            //ip2port_dmac.apply();
        }
        else if(meta.is_from_nfv && hdr.metadata.is_update == 1) {
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
        if(meta.apply_dst) {
            ip2port_dmac.apply();
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
