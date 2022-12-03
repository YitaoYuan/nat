#include <cstdio>
#include <cstring>
#include <pcap/pcap.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <unordered_map>
#include <queue>
#include <cstdlib>
#include <arpa/inet.h>

#include "../common/type.h"
#include "../common/hash.hpp"
#include "../common/list.hpp"
#include "../common/checksum.hpp"
#include "../common/heavy_hitter.hpp"

#include "shared_metadata.h"
#include "nat_hdr.h"



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


pcap_t *device;
// for regular packet
u8 buf[MAX_FRAME_SIZE] __attribute__ ((aligned (64)));
// for updating message
u8 metadata_buf[sizeof(ethernet_t) + sizeof(metadata_t)] __attribute__ ((aligned (64)));
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
heavy_hitter_t<hh_cnt_t, flow_entry_t*, 8, 512, SHARED_AGING_TIME_US/20> heavy_hitter[SWITCH_FLOW_NUM];

void heavy_hitter_count(flow_num_t id_index, flow_entry_t* entry, hh_cnt_t cnt, host_time_t timestamp)
{
    heavy_hitter[id_index].count(entry, cnt, timestamp);
}

flow_entry_t* heavy_hitter_get(flow_num_t id_index)
{
    if(heavy_hitter[id_index].size == 0)
        return NULL;
    flow_entry_t *entry = heavy_hitter[id_index].entry[0].id;
    if(entry->type == list_type::inuse && entry->id_index_host == id_index)
        return entry;
        // if this has timeout, it will be locked and will not be moved to list "avail"
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

    char *charmap = new char[SWITCH_FLOW_NUM];
    memset(charmap, 0, SWITCH_FLOW_NUM);
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
            if(charmap[entry.val_index_host] == 3)
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
    delete [] charmap;

    wait_set_head.l = wait_set_head.r = &wait_set_head;

    for(flow_num_t i = 0; i < SWITCH_FLOW_NUM; i++)
        heavy_hitter[i].init(timestamp);
}

void send_back(hdr_t * hdr, size_t len)
{
    //debug_printf("send_back\n");
    memcpy(hdr->ethernet.dst_addr, SWITCH_INNER_MAC, sizeof(hdr->ethernet.dst_addr));
    memcpy(hdr->ethernet.src_addr, NF_INNER_MAC, sizeof(hdr->ethernet.src_addr));
    pcap_sendpacket(device, (u_char *)hdr, len);
}

void send_update(flow_num_t index)
{
    hdr_t *hdr = (hdr_t *)metadata_buf;
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
    send_back(hdr, sizeof(hdr->ethernet) + sizeof(hdr->metadata));

    debug_printf("\nsend update\n");
    //debug_printf("primary\n");
    //print_map(wait_set[index].primary_map.id, ntohs(wait_set[index].primary_map.eport), index);
    debug_printf("old map:\n");
    print_map(wait_set[index].old_flow->map, index);
    debug_printf("new map:\n");
    print_map(wait_set[index].new_flow->map, index);
    
    debug_printf("version %x -> %x\n", hdr->metadata.old_version, hdr->metadata.new_version);
}

void try_add_update(flow_num_t wait_set_index, metadata_t &metadata, host_time_t timestamp)
{
    if(!wait_set[wait_set_index].is_waiting && timestamp - wait_set[wait_set_index].last_req_time_host >= SWAP_TIME_US) {
        flow_entry_t *new_entry = heavy_hitter_get(wait_set_index);

        if(new_entry == NULL) {
            return;
        }

        assert(metadata.map.val.wan_port != 0);//If we have preload process, this is always true.

        auto val_map_it = val_map.find({metadata.map.val.wan_addr, metadata.map.val.wan_port});
        assert(val_map_it != val_map.end());

        flow_entry_t *old_entry = val_map_it->second;
        assert(old_entry->type == list_type::sw);

        wait_set[wait_set_index] = {new_entry, old_entry, 
#ifdef REJECT_TEST
                                    metadata.old_version ^ 0xAA, // make version mismatch
#else
                                    metadata.old_version, 
#endif
                                    timestamp, timestamp, 
                                    true, NULL, NULL};
            
        // map entry
        new_entry->is_waiting = 1;// locked, it will not be moved to list "avail" immediately
        old_entry->is_waiting = 1;

        assert(old_entry->map.id.src_addr != 0);
        bool ret = id_map.insert(make_pair(old_entry->map.id, old_entry)).second;
        assert(ret);

        list_insert_before(&wait_set_head, &wait_set[wait_set_index]);// == push_back
        send_update(wait_set_index);
    }
}

void update_sw_count(hdr_t * hdr, host_time_t timestamp)
{
    flow_num_t index_host = ntohl(hdr->metadata.index);
    if(sw_entry[index_host]->is_waiting) return;
    if(memcmp(&sw_entry[index_host]->map.val, &hdr->metadata.map.val, sizeof(flow_val_t)) != 0){
        fprintf(stderr, "WARNING: switch's entry mismatch.\n");
        return;
    }

    switch_counter_t &old_cnt = sw_cnt[index_host];
    switch_counter_t new_cnt = hdr->metadata.main_flow_count;
    switch_counter_t diff = new_cnt - old_cnt;

    old_cnt = new_cnt;
    sw_entry[index_host]->map.id = hdr->metadata.map.id;
    heavy_hitter_count(index_host, sw_entry[index_host], diff, timestamp);
}

void forward_process(host_time_t timestamp, len_t packet_len, hdr_t * hdr)
{
// verify 
    bool is_tcp = hdr->ip.protocol == TCP_PROTOCOL;
    if((is_tcp && packet_len < MIN_TCP_LEN) || (!is_tcp && packet_len < MIN_UDP_LEN))
        return;

// heavy_hitter for main_flow
    update_sw_count(hdr, timestamp);
    
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
            fprintf(stderr, "Warning: Too full to allocate an entry for a new flow.\n");
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
    try_add_update(entry->id_index_host, metadata, timestamp);

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
    send_back(hdr, packet_len);
}

void backward_process(host_time_t timestamp, len_t packet_len, hdr_t * hdr)
{
// verify
    bool is_tcp = hdr->ip.protocol == TCP_PROTOCOL;
    if((is_tcp && packet_len < MIN_TCP_LEN) || (!is_tcp && packet_len < MIN_UDP_LEN))
        return;
// heavy_hitter for main_flow
    update_sw_count(hdr, timestamp);

    flow_id_t flow_id = {hdr->ip.src_addr, hdr->ip.dst_addr, 
                        hdr->L4_header.udp.src_port, hdr->L4_header.udp.dst_port, // the same as tcp
                        hdr->ip.protocol, (u8)0};

    auto val_map_it = val_map.find({flow_id.dst_addr, flow_id.dst_port});
    if(val_map_it == val_map.end()) return;// no such WAN addr & port

    flow_entry_t *entry = val_map_it->second;
    if(!(entry->type == list_type::inuse || (entry->type == list_type::sw && entry->is_waiting))) return;

// match
    if(entry->map.id.dst_addr != flow_id.src_addr || 
        entry->map.id.dst_port != flow_id.src_port ||
        entry->map.id.protocol != flow_id.protocol)
        return; // drop on mismatch

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
    try_add_update(entry->val_index_host, metadata, timestamp);

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
    send_back(hdr, packet_len);
}

void ack_process(host_time_t timestamp, len_t packet_len, hdr_t * hdr)
{
    metadata_t &metadata = hdr->metadata;

    flow_num_t index = ntohl(metadata.index);

    //debug_printf("2\n");
    wait_entry_t *wait_entry = &wait_set[index];
    if(!wait_entry -> is_waiting) return; // Redundant ACK
    //debug_printf("3\n");
    // mismatch
    if(wait_entry->old_version != metadata.old_version) 
        return;
    //debug_printf("4\n");

    flow_entry_t *entry_sw = wait_entry->old_flow;
    flow_entry_t *entry_nf = wait_entry->new_flow;

    assert(entry_sw->type == list_type::sw);
    assert(entry_nf->type == list_type::inuse);

    entry_nf->is_waiting = 0;
    entry_sw->is_waiting = 0;
    wait_entry->is_waiting = 0;

    list_erase(wait_entry);

    if(!metadata.main_flow_count) {// reject
        auto erase_res = id_map.erase(entry_sw->map.id);
        assert(erase_res);
    }
    else { // accept
        entry_sw->type = list_type::inuse;
        entry_nf->type = list_type::sw;

        entry_sw->timestamp_host = timestamp;

        list_move_to_back(&inuse_head, entry_sw);// sw->avail
        list_move_to_back(&sw_head, entry_nf);// inuse->sw

        auto erase_res = id_map.erase(entry_nf->map.id);
        assert(erase_res); 

        sw_entry[index] = entry_nf;
    }

    debug_printf("\nreceive ACK (%s)\n", hdr->metadata.main_flow_count? "accept": "reject");
    debug_printf("old map:\n");
    print_map(entry_sw->map, index);
    debug_printf("new map:\n");
    print_map(entry_nf->map, index);
    debug_printf("old_version %x\n", wait_entry->old_version);
}

void do_aging(host_time_t timestamp)
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

void update_wait_set(host_time_t timestamp)
{
    while(!list_empty(&wait_set_head))
    {
        wait_entry_t *entry = list_front(&wait_set_head);
        if(timestamp - entry->last_req_time_host <= WAIT_TIME_US) break;

        // prevent the worst case: switch should response in time no matter it is an accept or reject
        if(timestamp - entry->first_req_time_host > AGING_TIME_US) report_wait_time_too_long();

        entry->last_req_time_host = timestamp;

        send_update(entry->new_flow->id_index_host);// == (entry - &wait_set_head)
        list_move_to_back(&wait_set_head, entry);
    }
}

void nat_process(host_time_t timestamp, len_t packet_len, hdr_t * hdr)
{
    do_aging(timestamp);

    if(packet_len < PACKET_WITH_META_LEN) 
        return;
        
    if(hdr->ethernet.ether_type != htons(TYPE_METADATA)) 
        return;
    
    // only check checksum of header update
    net_checksum_calculator sum;
    sum.add(&hdr->metadata, sizeof(hdr->metadata));
    if(!sum.correct()) {
        fprintf(stderr, "Warning: Receive a packet with bad checksum, drop.\n");
        return;
    }
    
    if(hdr->metadata.map.id.zero != 0) {
        fprintf(stderr, "Error: Zero field of packet has non-zero value.\n");
        return;
    }

    if(hdr->metadata.type != 6 && packet_len < MIN_IP_LEN)
        return;
    
    if(ntohl(hdr->metadata.index) >= SWITCH_FLOW_NUM)
        return;

    if(hdr->metadata.type == 6)
        ack_process(timestamp, packet_len, hdr);
    else if(hdr->metadata.type == 4) 
        forward_process(timestamp, packet_len, hdr);
    else if(hdr->metadata.type == 5) 
        backward_process(timestamp, packet_len, (hdr_t *) hdr);
}

host_time_t get_mytime()
{
    timespec tm;
    clock_gettime(CLOCK_MONOTONIC, &tm); // don't use pcap's clock
    return (host_time_t)(tm.tv_sec*1000000ull+tm.tv_nsec/1000);
}

void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    fprintf(stderr, "%d %d\n", (int)h->caplen, (int)h->len);
    //h->ts.tv_sec/tv_usec
    //h->caplen
    //h->len
    if(h->caplen != h->len) return;
    memcpy(buf, bytes, h->len);

    nat_process(get_mytime(), h->len, (hdr_t*)buf);
}

int main(int argc, char **argv)
{
    assert((long long)buf % 64 == 0);
    if(argc != 2) {
        printf("Usage: nf ifname\n");
        return 0;
    }
    char *dev_name = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE]; 
    device = pcap_open_live(dev_name, MAX_FRAME_SIZE, 1, 1, errbuf);
    
    if(device == NULL) {
        printf("cannot open device\n");
        puts(errbuf);
        return 0;
    }

    signal(SIGINT, stop);

    nf_init(get_mytime());

    pcap_setnonblock(device, 1, errbuf);
    
    while(1) {
        pcap_dispatch(device, 16, pcap_handle, NULL);// process at most 4 packets

        update_wait_set(get_mytime());
    }
    
    return 0;
}
