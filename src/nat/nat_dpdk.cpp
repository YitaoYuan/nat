#include <cstdio>
#include <cstring>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <unordered_map>
#include <queue>
#include <cstdlib>
#include <arpa/inet.h>

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "shared_metadata.h"
#include "nat_hdr.h"

#include "../common/process_buf.hpp"
#include "../common/type.h"
#include "../common/hash.hpp"
#include "../common/list.hpp"
#include "../common/checksum.hpp"
#include "../common/heavy_hitter.hpp"
#include "../common/sysutil.hpp"

#ifdef DEBUG
#define debug_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug_printf(...)
#endif

using std::unordered_map;
using std::queue;
using std::make_pair;
using std::swap;
using std::max;
using std::min;


/*
 * All these constants are in host's byte order
 */

const ip_addr_t WAN_ADDR_BASE = SHARED_WAN_ADDR_BASE;
const port_t MIN_PORT = SHARED_MIN_PORT;

const flow_num_t SWITCH_FLOW_NUM = SHARED_SWITCH_FLOW_NUM;
const flow_num_t TOTAL_FLOW_NUM = SHARED_TOTAL_FLOW_NUM;

const host_time_t AGING_TIME_US = SHARED_AGING_TIME_US;
const host_time_t WAIT_TIME_US = 10000;// 10 ms
const host_time_t SWAP_TIME_US = AGING_TIME_US / 10;

const u16 TYPE_IPV4 = 0x800;
const u16 TYPE_METADATA = SHARED_TYPE_METADATA;

const u8 TCP_PROTOCOL = 0x06;
const u8 UDP_PROTOCOL = 0x11;

const u32 MAX_FRAME_SIZE = 1514 + sizeof(metadata_t);
const size_t PACKET_WITH_META_LEN = sizeof(ethernet_t) + sizeof(metadata_t);
const size_t MIN_IP_LEN = PACKET_WITH_META_LEN + sizeof(ip_t);
const size_t MIN_UDP_LEN = MIN_IP_LEN + sizeof(udp_t);
const size_t MIN_TCP_LEN = MIN_IP_LEN + sizeof(tcp_t);

const u32 MAX_BORROW_RETRY = 3;

enum list_type: u8{
    avail = 0,
    inuse = 1,
    sw = 2
};

struct flow_entry_t{
    map_entry_t map;// net
    flow_num_t val_index_host;
    flow_num_t id_index_host;// host
    host_time_t timestamp_host;// host 
    list_type type;// host
    bool is_waiting;
    flow_entry_t *l, *r;
};

struct wait_entry_t{
    flow_entry_t *new_flow;
    flow_entry_t *old_flow;// we don't care old_flow->id
    version_t old_version;// net (u8 is the same)
    host_time_t first_req_time_host;
    host_time_t last_req_time_host;// host
    bool is_waiting;
    wait_entry_t *l, *r;
};

template<typename T>
flow_num_t get_index(const T &data)
{
    my_hash<T> hasher;
    return hasher(data) % SWITCH_FLOW_NUM;
}


u8 SWITCH_INNER_MAC[6];
u8 NF_INNER_MAC[6];
/*
 * all bytes in these data structure are in network order
 */
unordered_map<flow_id_t, flow_entry_t*, my_hash<flow_id_t>, mem_equal<flow_id_t> >id_map;
unordered_map<flow_val_t, flow_entry_t*, my_hash<flow_val_t>, mem_equal<flow_val_t> >val_map;

flow_entry_t inuse_head, sw_head, avail_head[SWITCH_FLOW_NUM];
flow_entry_t flow_entry[TOTAL_FLOW_NUM];
flow_entry_t *sw_entry[SWITCH_FLOW_NUM];
switch_counter_t sw_cnt[SWITCH_FLOW_NUM];

wait_entry_t wait_set[SWITCH_FLOW_NUM];
wait_entry_t wait_set_head;

typedef unsigned short hh_cnt_t;
heavy_hitter_t<hh_cnt_t, flow_entry_t*, 8, 4096, SHARED_AGING_TIME_US/10> heavy_hitter[SWITCH_FLOW_NUM];

void heavy_hitter_count(flow_num_t id_index, flow_entry_t* entry, hh_cnt_t cnt, host_time_t timestamp)
{
    heavy_hitter[id_index].count(entry, cnt, timestamp);
}

flow_entry_t* heavy_hitter_get(flow_num_t id_index)
{
    if(heavy_hitter[id_index].size == 0) {
        return NULL;
    }
        
    flow_entry_t *entry = heavy_hitter[id_index].entry[0].id;
    if(entry->type == list_type::inuse && entry->id_index_host == id_index) {
        for(size_t i = 0; i < heavy_hitter[id_index].size; i++) {
            debug_printf("%d ", (int)heavy_hitter[id_index].entry[i].cnt);
        }
        debug_printf("\n");
        return entry;
    }
    return NULL;
}


void stop(int signo)
{
    _exit(0);
}

void print_map(map_entry_t flow_map, flow_num_t index)
{
    flow_id_t id = flow_map.id;
    flow_val_t val = flow_map.val;
    debug_printf("(src=%d.%d.%d.%d:%d, dst=%d.%d.%d.%d:%d, protocal=%d) -> (%d.%d.%d.%d:%d, index %d)\n", 
        ((u8*)&id.src_addr)[0],
        ((u8*)&id.src_addr)[1],
        ((u8*)&id.src_addr)[2],
        ((u8*)&id.src_addr)[3],
        ntohs(id.src_port),

        ((u8*)&id.dst_addr)[0],
        ((u8*)&id.dst_addr)[1],
        ((u8*)&id.dst_addr)[2],
        ((u8*)&id.dst_addr)[3],
        ntohs(id.dst_port),

        id.protocol,

        ((u8*)&val.wan_addr)[0],
        ((u8*)&val.wan_addr)[1],
        ((u8*)&val.wan_addr)[2],
        ((u8*)&val.wan_addr)[3],
        ntohs(val.wan_port),
        
        index
    );
}

void nf_init(host_time_t timestamp)
{       
    *(u16*)SWITCH_INNER_MAC = htons(SHARED_SWITCH_INNER_MAC_HI16);
    *(u32*)(SWITCH_INNER_MAC+2) = htonl(SHARED_SWITCH_INNER_MAC_LO32);
    *(u16*)NF_INNER_MAC = htons(SHARED_NF_INNER_MAC_HI16);
    *(u32*)(NF_INNER_MAC+2) = htonl(SHARED_NF_INNER_MAC_LO32);

    inuse_head.l = inuse_head.r = &inuse_head;
    sw_head.l = sw_head.r = &sw_head;

    for(flow_num_t i = 0; i < SWITCH_FLOW_NUM; i++) {
        avail_head[i].l = avail_head[i].r = &avail_head[i];
    }

    ip_addr_t wan_addr_base = WAN_ADDR_BASE;
    port_t min_port = MIN_PORT;
    flow_num_t port_num_per_addr = (1<<16) - min_port;
    
    assert(TOTAL_FLOW_NUM / port_num_per_addr < 128);

    char *charmap = (char*)calloc(SWITCH_FLOW_NUM, sizeof(char));

    int preload_num = 0;

    memset(sw_cnt, 0, sizeof(sw_cnt));

    for(flow_num_t i = 0; i < TOTAL_FLOW_NUM; i++) {// BUG fixed !! don't use "port <= PORT_MAX"
        ip_addr_t addr_offset = i / port_num_per_addr;
        ip_addr_t wan_addr = wan_addr_base - addr_offset;
        port_t wan_port = min_port + i % port_num_per_addr;

        flow_entry_t &entry = flow_entry[i];
        memset(&entry.map.id, 0, sizeof(entry.map.id));
        entry.map.val = {htonl(wan_addr), htons(wan_port)};
        entry.val_index_host = get_index(entry.map.val);
        entry.id_index_host = entry.val_index_host;
        entry.is_waiting = 0;

        if(!charmap[entry.val_index_host]) {
            preload_num ++;

            entry.type = list_type::sw;
            list_insert_before(&sw_head, &entry);
            sw_entry[entry.val_index_host] = &entry;
        }
        else {
#ifdef ONE_ENTRY_TEST
            if(charmap[entry.val_index_host] == 5)
                continue;
#endif
            entry.type = list_type::avail;
            list_insert_before(&avail_head[entry.val_index_host], &entry);
        }
        charmap[entry.val_index_host]++;

        val_map.insert(make_pair(entry.map.val, &entry));
    }
    
    char max_bucket_size = 0, min_bucket_size = 127;
    for(flow_num_t i = 0; i < SWITCH_FLOW_NUM; i++) {
        max_bucket_size = max(max_bucket_size, charmap[i]);
        min_bucket_size = min(min_bucket_size, charmap[i]);
    }
    printf("max_bucket_size: %d\nmin_bucket_size: %d\nnumber of pre-load entries: %d(%d%%)\n", 
        max_bucket_size, min_bucket_size, preload_num, preload_num*100/SWITCH_FLOW_NUM);
    if(min_bucket_size * 2 < max_bucket_size) {
        printf("WARNING: Your data's distribution is too uneven.\n");
    }
    free(charmap);

    wait_set_head.l = wait_set_head.r = &wait_set_head;

    for(flow_num_t i = 0; i < SWITCH_FLOW_NUM; i++)
        heavy_hitter[i].init(timestamp);
}

void send_back(struct rte_mbuf *buf, queue_process_buf *queue)
{
    hdr_t *hdr = rte_pktmbuf_mtod(buf, hdr_t *);
    memcpy(hdr->ethernet.dst_addr, SWITCH_INNER_MAC, sizeof(hdr->ethernet.dst_addr));
    memcpy(hdr->ethernet.src_addr, NF_INNER_MAC, sizeof(hdr->ethernet.src_addr));
    queue->send(buf);
}

void send_update(flow_num_t index, queue_process_buf *queue)
{
    struct rte_mbuf *buf = queue->alloc();
    buf->data_len = sizeof(ethernet_t) + sizeof(metadata_t);
    buf->pkt_len = buf->data_len;

    hdr_t *hdr = rte_pktmbuf_mtod(buf, hdr_t *);
    // MAC address is useless between nf & switch

    hdr->metadata.map = wait_set[index].new_flow->map;
    hdr->metadata.old_version = wait_set[index].old_version;
    hdr->metadata.new_version = (hdr->metadata.old_version & 0xf0) | ((hdr->metadata.old_version + 1) & 0x0f);

    hdr->metadata.type = 6;
    hdr->metadata.main_flow_count = 0;

    hdr->metadata.index = htonl(index);

    hdr->metadata.checksum = 0;// clear to recalculate

    net_checksum_calculator sum;
    sum.add(&hdr->metadata, sizeof(hdr->metadata));
    
    hdr->metadata.checksum = sum.checksum();

    hdr->ethernet.ether_type = htons(TYPE_METADATA);

    debug_printf("\nsend update\n");
    debug_printf("old map:\n");
    print_map(wait_set[index].old_flow->map, index);
    debug_printf("new map:\n");
    print_map(wait_set[index].new_flow->map, index);
    
    debug_printf("version %x -> %x\n", hdr->metadata.old_version, hdr->metadata.new_version);

    send_back(buf, queue);
}

void try_add_update(flow_num_t wait_set_index, metadata_t &metadata, host_time_t timestamp, queue_process_buf *queue)
{
    if(!wait_set[wait_set_index].is_waiting && timestamp - wait_set[wait_set_index].last_req_time_host >= SWAP_TIME_US) {
        
        flow_entry_t *new_entry = heavy_hitter_get(wait_set_index);

        if(new_entry == NULL) return;

        assert(metadata.map.val.wan_port != 0);//If we have preload process, this is always true.

        auto val_map_it = val_map.find({metadata.map.val.wan_addr, metadata.map.val.wan_port});
        assert(val_map_it != val_map.end());

        flow_entry_t *old_entry = val_map_it->second;
        assert(old_entry->type == list_type::sw);

        wait_set[wait_set_index] = {new_entry, old_entry, 
#ifdef REJECT_TEST
                                    metadata.old_version ^ 0xA0, // make inplace version mismatch
#else
                                    metadata.old_version, 
#endif
                                    timestamp, timestamp, 
                                    true, NULL, NULL};
            
        // map entry
        new_entry->is_waiting = 1;// locked, it will not be moved to list "avail" immediately
        old_entry->is_waiting = 1;

        assert(old_entry->map.id.src_addr != 0);
        auto ret = id_map.insert(make_pair(old_entry->map.id, old_entry));
        if(!ret.second) {
            fprintf(stderr, "(%x:%hu, %x:%hu, %d) already exists." ,
                ntohl(old_entry->map.id.src_addr), ntohs(old_entry->map.id.src_port),
                ntohl(old_entry->map.id.dst_addr), ntohs(old_entry->map.id.dst_port),
                old_entry->map.id.protocol);
        }
        assert(ret.second);

        list_insert_before(&wait_set_head, &wait_set[wait_set_index]);// == push_back
        send_update(wait_set_index, queue);
    }
}

void update_sw_count(hdr_t * hdr, host_time_t timestamp)
{
    flow_num_t index_host = ntohl(hdr->metadata.index);
    if(sw_entry[index_host]->is_waiting) return;
    if(memcmp(&sw_entry[index_host]->map.val, &hdr->metadata.map.val, sizeof(flow_val_t)) != 0){
        print_map(hdr->metadata.map, index_host);
        return;
    }

    switch_counter_t &old_cnt = sw_cnt[index_host];
    switch_counter_t new_cnt = hdr->metadata.main_flow_count;
    switch_counter_t diff = new_cnt - old_cnt;

    old_cnt = new_cnt;
    sw_entry[index_host]->map.id = hdr->metadata.map.id;
    heavy_hitter_count(index_host, sw_entry[index_host], diff, timestamp);
}

void forward_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    hdr_t* hdr = rte_pktmbuf_mtod(buf, hdr_t*);
// verify 
    bool is_tcp = hdr->ip.protocol == TCP_PROTOCOL;

// heavy_hitter for main_flow
    update_sw_count(hdr, timestamp);

    if(!sw_entry[ntohl(hdr->metadata.index)]->is_waiting && memcmp(&sw_entry[ntohl(hdr->metadata.index)]->map.val, &hdr->metadata.map.val, sizeof(flow_val_t)) != 0) {
        fprintf(stderr, "packet info out of date, drop.\n");
        queue->drop(buf);
        return;
    } 
    
    flow_id_t flow_id = {hdr->ip.src_addr, hdr->ip.dst_addr, 
                        hdr->L4_header.udp.src_port, hdr->L4_header.udp.dst_port, // the same as tcp
                        hdr->ip.protocol, (u8)0};

// allocate flow state for new flow    
    // things in map are in network byte order
    auto id_map_it = id_map.find(flow_id);
    if(id_map_it == id_map.end()) {// a new flow
        flow_num_t id_index_host;
#ifdef ONE_ENTRY_TEST
        id_index_host = 1;
#else
        id_index_host = get_index(flow_id);
#endif
        assert(id_index_host == ntohl(hdr->metadata.index));

        flow_num_t index_select = id_index_host;
        
        u32 retry = 0;
        while(list_empty(&avail_head[index_select])) {
            retry ++;
            if(retry > MAX_BORROW_RETRY) break;
            index_select = (flow_num_t)(rand() ^ (rand() << 16)) % SWITCH_FLOW_NUM;
        }

        if(list_empty(&avail_head[index_select])) {
            fprintf(stderr, "Warning: Too full to allocate an entry for a new flow, drop.\n");
            queue->drop(buf);
            return;// too full to allocate, drop
        }
        if(index_select != id_index_host) {
            debug_printf("Borrow an entry.\n");   
        }

        flow_entry_t *entry = list_front(&avail_head[index_select]);
        
        entry->map.id = flow_id;
        entry->id_index_host = id_index_host;
        entry->type = list_type::inuse;
        entry->is_waiting = 0;
        list_move_to_back(&inuse_head, entry);

        id_map_it = id_map.insert(make_pair(flow_id, entry)).first;
    }
// refresh flow's timestamp
    flow_entry_t *entry = id_map_it->second;
    entry->timestamp_host = timestamp;// host

    assert(entry->type == list_type::inuse || (entry->type == list_type::sw && entry->is_waiting));
// move to the tail of aging queue
    if(entry->type == list_type::inuse) {
        list_move_to_back(&inuse_head, entry);
    }

// heavy_hitter for this flow
    if(entry->id_index_host == entry->val_index_host) {
        // it is not a borrowed entry
        heavy_hitter_count(entry->val_index_host, entry, 1, timestamp);
    }
    

// translate
    net_checksum_calculator sum;

    sum.sub(&hdr->ip.src_addr, sizeof(ip_addr_t));
    hdr->ip.src_addr = entry->map.val.wan_addr;
    sum.add(&hdr->ip.src_addr, sizeof(ip_addr_t));

    hdr->ip.checksum = sum.checksum(&hdr->ip.checksum);
    if(is_tcp) {
        sum.sub(&hdr->L4_header.tcp.src_port);
        hdr->L4_header.tcp.src_port = entry->map.val.wan_port;// 
        sum.add(&hdr->L4_header.tcp.src_port);

        hdr->L4_header.tcp.checksum = sum.checksum(&hdr->L4_header.tcp.checksum);
    }
    else {
        sum.sub(&hdr->L4_header.udp.src_port);
        hdr->L4_header.udp.src_port = entry->map.val.wan_port;
        sum.add(&hdr->L4_header.udp.src_port);

        if(hdr->L4_header.udp.checksum != 0)// 0 is same for n & h
            hdr->L4_header.udp.checksum = sum.checksum(&hdr->L4_header.udp.checksum);
    }

    metadata_t &metadata = hdr->metadata;
// try add update
    try_add_update(entry->id_index_host, metadata, timestamp, queue);

// modify flieds in metadata
    net_checksum_calculator metadata_sum;
    metadata_sum.sub(&metadata.type);// default 2 bytes
    metadata.type = 2;
    metadata.main_flow_count = 0;
    metadata_sum.add(&metadata.type);

    metadata_sum.sub(&metadata.map, sizeof(metadata.map));
    metadata.map = entry->map;
    metadata_sum.add(&metadata.map, sizeof(metadata.map));

    metadata.checksum = metadata_sum.checksum(&metadata.checksum);

#ifdef PATH_TEST
    // this does not change checksum
    if(is_tcp) swap(*(checksum_t*)(hdr->L4_header.tcp.payload), 
                    *(checksum_t*)(hdr->L4_header.tcp.payload + 2));
    else swap(*(checksum_t*)(hdr->L4_header.udp.payload),
            *(checksum_t*)(hdr->L4_header.udp.payload + 2));
#endif
// send back
    send_back(buf, queue);
}

void backward_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    hdr_t* hdr = rte_pktmbuf_mtod(buf, hdr_t*);
// verify
    bool is_tcp = hdr->ip.protocol == TCP_PROTOCOL;

// heavy_hitter for main_flow
    update_sw_count(hdr, timestamp);

    if(!sw_entry[ntohl(hdr->metadata.index)]->is_waiting && memcmp(&sw_entry[ntohl(hdr->metadata.index)]->map.val, &hdr->metadata.map.val, sizeof(flow_val_t)) != 0) {
        fprintf(stderr, "packet info out of date, drop.\n");
        queue->drop(buf);
        return;
    } 

    flow_id_t flow_id = {hdr->ip.src_addr, hdr->ip.dst_addr, 
                        hdr->L4_header.udp.src_port, hdr->L4_header.udp.dst_port, // the same as tcp
                        hdr->ip.protocol, (u8)0};

    auto val_map_it = val_map.find({flow_id.dst_addr, flow_id.dst_port});
    if(val_map_it == val_map.end()) {
        queue->drop(buf);
        return;// no such WAN addr & port
    }

    flow_entry_t *entry = val_map_it->second;
    if(!(entry->type == list_type::inuse || (entry->type == list_type::sw && entry->is_waiting))) return;

// match
    if(entry->map.id.dst_addr != flow_id.src_addr || 
        entry->map.id.dst_port != flow_id.src_port ||
        entry->map.id.protocol != flow_id.protocol) {
        queue->drop(buf);
        return; // drop on mismatch
    }
        

    assert(entry->val_index_host == ntohl(hdr->metadata.index));
    /*
    auto it = map.find(flow_id);
    assert(it != map.end() && it->second == entry);// because it is in use
    */
    
// refresh flow's timestamp
    entry->timestamp_host = timestamp;

// move to the tail of aging queue
    if(entry->type == list_type::inuse) {
        list_move_to_back(&inuse_head, entry);
    }

// heavy hitter detect
    if(entry->id_index_host == entry->val_index_host) {
        // it is not a borrowed entry
        heavy_hitter_count(entry->val_index_host, entry, 1, timestamp);
    }
    
// translate
    net_checksum_calculator sum;

    sum.sub(&hdr->ip.dst_addr, sizeof(hdr->ip.dst_addr));
    hdr->ip.dst_addr = entry->map.id.src_addr;
    sum.add(&hdr->ip.dst_addr, sizeof(hdr->ip.dst_addr));

    hdr->ip.checksum = sum.checksum(&hdr->ip.checksum);
    if(is_tcp) {
        sum.sub(&hdr->L4_header.tcp.dst_port);
        hdr->L4_header.tcp.dst_port = entry->map.id.src_port;
        sum.add(&hdr->L4_header.tcp.dst_port);

        hdr->L4_header.tcp.checksum = sum.checksum(&hdr->L4_header.tcp.checksum);
    }
    else {
        sum.sub(&hdr->L4_header.udp.dst_port);
        hdr->L4_header.udp.dst_port = entry->map.id.src_port;
        sum.add(&hdr->L4_header.udp.dst_port);

        if(hdr->L4_header.udp.checksum != 0)
            hdr->L4_header.udp.checksum = sum.checksum(&hdr->L4_header.udp.checksum);
    }

    metadata_t &metadata = hdr->metadata;
    try_add_update(entry->val_index_host, metadata, timestamp, queue);

// modify flieds in metadata
    net_checksum_calculator metadata_sum;
    metadata_sum.sub(&metadata.type);// default 2 bytes
    metadata.type = 3;
    metadata.main_flow_count = 0;
    metadata_sum.add(&metadata.type);

    metadata_sum.sub(&metadata.map, sizeof(metadata.map));
    metadata.map = entry->map;
    metadata_sum.add(&metadata.map, sizeof(metadata.map));

    metadata_sum.sub(&metadata.index, sizeof(metadata.index));
    metadata.index = htonl(entry->id_index_host);// original index may be borrowed
    metadata_sum.add(&metadata.index, sizeof(metadata.index));

    metadata.checksum = metadata_sum.checksum(&metadata.checksum);

#ifdef PATH_TEST
    if(is_tcp) swap(*(checksum_t*)(hdr->L4_header.tcp.payload + 4), 
                    *(checksum_t*)(hdr->L4_header.tcp.payload + 6));
    else swap(*(checksum_t*)(hdr->L4_header.udp.payload + 4), 
            *(checksum_t*)(hdr->L4_header.udp.payload + 6));
#endif

// send back
    send_back(buf, queue);
}

void ack_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    hdr_t* hdr = rte_pktmbuf_mtod(buf, hdr_t*);

    metadata_t &metadata = hdr->metadata;

    u8 nf_new_version = metadata.new_version;
    u8 nf_old_version = (metadata.new_version & 0xf0) | ((metadata.new_version - 1) & 0x0f);
    u8 switch_old_version = metadata.old_version;
    const int reject_flag = 0;
    const int accept_flag = 1;
    int update_flag = -1;

    if (switch_old_version == nf_old_version || ((switch_old_version & 0x0f) == (nf_new_version & 0x0f))) {
        update_flag = accept_flag;
    }
    else if((switch_old_version & 0x0f) == (nf_old_version & 0x0f)) {
        update_flag = reject_flag;
    }
    else {// out-of-date update
        fprintf(stderr, "Detect an out-of-date update\n");
        fprintf(stderr, "switch's version %2x, update's version %2x -> %2x\n", 
            (u32)switch_old_version, 
            (u32)nf_old_version, 
            (u32)nf_new_version);
        queue->drop(buf);
        return;
    }

    flow_num_t index = ntohl(metadata.index);

    wait_entry_t *wait_entry = &wait_set[index];
    if(!wait_entry -> is_waiting) {
        queue->drop(buf);
        fprintf(stderr, "Redundant ACK, drop.\n");
        return; // Redundant ACK
    }
    // mismatch
    if(wait_entry->old_version != nf_old_version) {
        queue->drop(buf);
        fprintf(stderr, "wait_entry's version mismatch, drop.\n");
        return;
    }

    flow_entry_t *entry_sw = wait_entry->old_flow;
    flow_entry_t *entry_nf = wait_entry->new_flow;

    assert(entry_sw->type == list_type::sw);
    assert(entry_nf->type == list_type::inuse);

    entry_nf->is_waiting = 0;
    entry_sw->is_waiting = 0;
    wait_entry->is_waiting = 0;

    list_erase(wait_entry);

    if(update_flag == reject_flag) {// reject
        auto erase_res = id_map.erase(entry_sw->map.id);
        assert(erase_res);
    }
    else if(update_flag == accept_flag) { // accept
        entry_sw->type = list_type::inuse;
        entry_nf->type = list_type::sw;

        entry_sw->timestamp_host = timestamp;

        list_move_to_back(&inuse_head, entry_sw);
        list_move_to_back(&sw_head, entry_nf);

        auto erase_res = id_map.erase(entry_nf->map.id);
        assert(erase_res); 

        sw_entry[index] = entry_nf;
    }
    
    debug_printf("\nreceive ACK (%s)\n", update_flag == accept_flag ? "accept": "reject");
    debug_printf("old map:\n");
    print_map(entry_sw->map, index);
    debug_printf("new map:\n");
    print_map(entry_nf->map, index);
    debug_printf("switch's version %2x, update's version %2x -> %2x\n", 
            (u32)switch_old_version, 
            (u32)nf_old_version, 
            (u32)nf_new_version);
    // don't forget this !!!
    queue->drop(buf);
}

void nf_aging(host_time_t timestamp)
{
    for(flow_entry_t *entry = inuse_head.r, *nxt; 
        entry != &inuse_head; entry = nxt) {
        
        nxt = entry->r;// must first calculate address nxt, or SGfault may happen 

        if(timestamp - entry->timestamp_host <= AGING_TIME_US) break;

        if(entry->is_waiting) continue;// wait to swap to switch

        assert(entry->type == list_type::inuse);

        list_move_to_back(&avail_head[entry->val_index_host], entry);
        entry->type = list_type::avail;
        auto erase_res = id_map.erase(entry->map.id);
        assert(erase_res == 1); 
    }
    // for debug
    static host_time_t last_timestamp = 0;
    if(timestamp - last_timestamp < 1000000) return;
    last_timestamp = timestamp;    


    debug_printf("\n");
    debug_printf("old\n");
    flow_entry_t *entry = list_front(&inuse_head);
    int cnt = 0;
    while(entry != &inuse_head) {
        print_map(entry->map, entry->id_index_host);
        cnt++;
        entry = entry->r;
    }
    debug_printf("new\n");
    debug_printf("%d active flows\n", cnt);
}

void report_wait_time_too_long()
{
    fprintf(stderr, "Wait time too long!");
    exit(0);
}

void nf_update_wait_set(host_time_t timestamp, queue_process_buf *queue)
{
    while(!list_empty(&wait_set_head))
    {
        wait_entry_t *entry = list_front(&wait_set_head);
        if(timestamp - entry->last_req_time_host <= WAIT_TIME_US) break;

        // prevent the worst case: switch should response in time no matter it is an accept or reject
        if(timestamp - entry->first_req_time_host > AGING_TIME_US) report_wait_time_too_long();

        entry->last_req_time_host = timestamp;

        send_update(entry->new_flow->id_index_host, queue);// == (entry - &wait_set_head)
        list_move_to_back(&wait_set_head, entry);
    }
}

void nf_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    if(buf->pkt_len != buf->data_len) {queue->drop(buf); return;}

    if(buf->pkt_len < PACKET_WITH_META_LEN) {queue->drop(buf); return;}

    hdr_t* hdr = rte_pktmbuf_mtod(buf, hdr_t*);
        
    if(hdr->ethernet.ether_type != htons(TYPE_METADATA)) {queue->drop(buf); return;}
    
    // only check checksum of header update
    net_checksum_calculator sum;
    sum.add(&hdr->metadata, sizeof(hdr->metadata));
    if(!sum.correct()) {
        fprintf(stderr, "Warning: Receive a packet with bad checksum, drop.\n");
        queue->drop(buf); 
        return;
    }
    
    if(hdr->metadata.map.id.zero != 0) {
        fprintf(stderr, "Error: Zero field of packet has non-zero value.\n");
        queue->drop(buf); 
        return;
    }

    if(hdr->metadata.type != 6) {
        if(buf->pkt_len < MIN_IP_LEN) {queue->drop(buf); return;}
        else if(hdr->ip.protocol == TCP_PROTOCOL) {
            if(buf->pkt_len < MIN_TCP_LEN) {queue->drop(buf); return;}
        } 
        else if(hdr->ip.protocol == UDP_PROTOCOL) {
            if(buf->pkt_len < MIN_UDP_LEN) {queue->drop(buf); return;}
        }
        else {queue->drop(buf); return;}
    }
    
    if(ntohl(hdr->metadata.index) >= SWITCH_FLOW_NUM) {queue->drop(buf); return;}

    if(hdr->metadata.type == 6)
        ack_process(timestamp, buf, queue);
    else if(hdr->metadata.type == 4) 
        forward_process(timestamp, buf, queue);
    else if(hdr->metadata.type == 5) 
        backward_process(timestamp, buf, queue);
}

host_time_t get_mytime()
{
    return (host_time_t)(rte_get_timer_cycles() / (rte_get_timer_hz() / 1000000));
}

void
lcore_main(uint16_t port, struct rte_mempool *mbuf_pool)
{
    if (rte_eth_dev_socket_id(port) >= 0 &&
        rte_eth_dev_socket_id(port) != (int)rte_socket_id())
            printf("WARNING, port %u is on remote NUMA node to "
                    "polling thread.\n\tPerformance will "
                    "not be optimal.\n", port);
    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
            rte_lcore_id());

    queue_process_buf queue(mbuf_pool, port, 0, BURST_SIZE, BURST_SIZE * 2);

    nf_init(get_mytime());

    while(true) {
        nf_aging(get_mytime());
        nf_update_wait_set(get_mytime(), &queue);

        struct rte_mbuf *buf = queue.receive();
        if(buf != NULL)
            nf_process(get_mytime(), buf, &queue);

        if(queue.total_rx_nb + queue.total_alloc_nb != queue.total_tx_nb + queue.total_drop_nb) {
            fprintf(stderr, "rx: %u, tx: %u, drop: %u, alloc: %u\n", 
                queue.total_rx_nb, queue.total_tx_nb, queue.total_drop_nb, queue.total_alloc_nb);
            fprintf(stderr, "WARNING: total_rx_nb + total_alloc_nb != total_tx_nb + total_drop_nb. \n\
Either some packets are not recycled or some external packets send/droped by this queue.\n\
You can ignore this warning if you have cross-queue packets.\n");
        }
    }
}
/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
//test -c 0x100000 -n 4 --socket-mem=0,8192 -d librte_mempool.so --huge-unlink --log-level=4
// -c 设置应用使用的CPU集合，注意lcore和cpu不一定是一对一的，但通常是一对一的。
// -n 内存通道数
// --socket-mem 预分配的每个socket内存大小，逗号隔开
// -d 加载额外驱动
// --huge-unlink 创建大页文件后Unlink （暗指不支持多进程）
// --log-level 日志级别

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
};

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    if (!rte_eth_dev_is_valid_port(port))
        return -1;
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
                port, strerror(-retval));
        return retval;
    }
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;
    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }
    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;
    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);
    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;
    return 0;
}

#define MY_RTE_ARG_LEN 256
#define MY_RTE_ARG_NUM 32

char rte_arg[MY_RTE_ARG_LEN];
char *arg_tail = rte_arg;
char static_arg[] = "-n 4 -d librte_mempool.so --huge-unlink";
char *rte_argv[MY_RTE_ARG_NUM];

void arg_append(const char *str)
{
    size_t len = strlen(str);
    assert((arg_tail - rte_arg) + len < MY_RTE_ARG_LEN);
    strcpy(arg_tail, str);
    arg_tail += len;
}

void init(char *nic_name, uint16_t *portid, struct rte_mempool **mbuf_pool)
{
    // generate args
    char *businfo;
    int numanode, numanode_num;
    char *cpu_list;
    char *core_mask;
    int nb_core = 1;
    assert(nic_getbusinfo_by_name(nic_name, &businfo) == 0);
    numanode = nic_getnumanode_by_businfo(businfo);
    assert(!(numanode < 0));
    assert(nic_getcpus_by_numa(numanode, &cpu_list) == 0);
    assert(cpu_getmask(cpu_list, nb_core, &core_mask) == nb_core);

    numanode_num = get_numanode_num();
    assert(numanode_num > 0);

    arg_append("test");
    arg_append(" -c ");
    arg_append(core_mask);
    arg_append(" --socket-mem=");
    for(int i = 0; i < numanode_num; i++) {
        arg_append(i==numanode?"8192":"0");
        arg_append(i==numanode_num-1?" ":",");
    }
    arg_append(static_arg);
    printf("RTE args: %s\n", rte_arg);
    
    // split & install args
    int rte_argc = 0;
    for(char *arg = strtok(rte_arg, " "); arg != NULL; arg = strtok(NULL, " ")) {
        rte_argv[rte_argc++] = arg;
        assert(rte_argc < MY_RTE_ARG_NUM);
    }
    //printf("%d\n", rte_eal_init(rte_argc, rte_argv));
    assert(rte_eal_init(rte_argc, rte_argv) == rte_argc - 1);
    assert(rte_lcore_count() == 1);

    // mempool & port init
    assert(!(rte_eth_dev_get_port_by_name(businfo, portid) < 0));
    *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    assert(port_init(*portid, *mbuf_pool) == 0);
}

int
main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("Usage: test <interface_name>\n");
        return 0;
    }
    char *ifname = argv[1];
    uint16_t portid;
    struct rte_mempool *mbuf_pool;
    init(ifname, &portid, &mbuf_pool);
    lcore_main(portid, mbuf_pool);
    /* clean up the EAL */
    rte_eal_cleanup();
    return 0;
}