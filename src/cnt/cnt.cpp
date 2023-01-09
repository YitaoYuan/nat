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
/* DPDK */
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "../common/process_buf.hpp"

/* system utilities */
#include "../common/sysutil.hpp"

/* custom data structure */
#include "shared_metadata.h"
#include "../common/type.h"
#include "cnt_hdr.h"
#include "../common/hash.hpp"
#include "../common/list.hpp"
#include "../common/checksum.hpp"
#include "../common/heavy_hitter.hpp"

/* program skeleton */
#include "../common/dpdk_skeleton.hpp"

#ifdef DEBUG
#define debug_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug_printf(...)
#endif

using std::unordered_map;
using std::make_pair;
using std::swap;
using std::max;
using std::min;
using std::vector;

/*
 * All these constants are in host's byte order
 */
const flow_num_t SWITCH_FLOW_NUM = SHARED_SWITCH_FLOW_NUM;
const flow_num_t TOTAL_FLOW_NUM = SHARED_TOTAL_FLOW_NUM;

const host_time_t AGING_TIME_US = SHARED_AGING_TIME_US;
const host_time_t WAIT_TIME_US = SHARED_WAIT_TIME_US;// 10 ms
const host_time_t SWAP_TIME_US = AGING_TIME_US / 5;

const u16 TYPE_IPV4 = 0x800;
const u16 TYPE_METADATA = SHARED_TYPE_METADATA;

const u8 TCP_PROTOCOL = 0x06;
const u8 UDP_PROTOCOL = 0x11;

const size_t PACKET_WITH_META_LEN = sizeof(ethernet_t) + sizeof(metadata_t);
const size_t MIN_IP_LEN = PACKET_WITH_META_LEN + sizeof(ip_t);
const size_t MIN_UDP_LEN = MIN_IP_LEN + sizeof(udp_t);
const size_t MIN_TCP_LEN = MIN_IP_LEN + sizeof(tcp_t);

enum list_type: u8{
    avail = 0,
    inuse = 1,
    sw = 2
};

struct flow_entry_t{
    map_entry_t map;// net
    flow_num_t index_host;
    host_time_t timestamp_host;// host 
    list_type type;// host
    bool is_waiting;
    flow_entry_t *l, *r;
};

struct wait_entry_t{
    flow_entry_t *new_flow;
    flow_entry_t *old_flow;
    version_t old_version;// net (u8 is the same)
    host_time_t first_req_time_host;
    host_time_t last_req_time_host;// host
    bool is_waiting;
    bool is_closing;// this is for counter only 
    wait_entry_t *l, *r;
};

u8 SWITCH_INNER_MAC[6];
u8 NF_INNER_MAC[6];
/*
 * all bytes in these data structure are in network order
 */
/* Consistent Hashing: Per-flow entry. */
unordered_map<flow_id_t, flow_entry_t*, my_hash<flow_id_t, SHARED_SWITCH_CRC_POLY>, mem_equal<flow_id_t> >id_map;

flow_entry_t inuse_head, sw_head, avail_head;
flow_entry_t flow_entry[TOTAL_FLOW_NUM];
flow_entry_t *sw_entry[SWITCH_FLOW_NUM];
switch_counter_t sw_cnt[SWITCH_FLOW_NUM];
version_t sw_version[SWITCH_FLOW_NUM];

wait_entry_t wait_set[SWITCH_FLOW_NUM];
wait_entry_t wait_set_head;

typedef unsigned short hh_cnt_t;
heavy_hitter_t<hh_cnt_t, flow_entry_t*, 8, 4096, SHARED_AGING_TIME_US/10> heavy_hitter[SWITCH_FLOW_NUM];

int pkt_cnt, update_cnt, wait_set_size;
int wait_set_inc, wait_set_dec;

template<typename T>
flow_num_t get_index(const T &data)
{
    my_hash<T, SHARED_SWITCH_CRC_POLY> hasher;
    return hasher(data) % SWITCH_FLOW_NUM;
}


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
    if(entry->map.id.protocol == 0 && heavy_hitter[id_index].size >= 2) {
        entry = heavy_hitter[id_index].entry[1].id;
    }
    
    if(entry->type == list_type::inuse) {
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
    // flow_id_t id = flow_map.id;
    // flow_val_t val = flow_map.val;
    // debug_printf("(src=%d.%d.%d.%d:%d, dst=%d.%d.%d.%d:%d, protocal=%d) -> (%d.%d.%d.%d, index %d)\n", 
    //     ((u8*)&id.src_addr)[0],
    //     ((u8*)&id.src_addr)[1],
    //     ((u8*)&id.src_addr)[2],
    //     ((u8*)&id.src_addr)[3],
    //     ntohs(id.src_port),

    //     ((u8*)&id.dst_addr)[0],
    //     ((u8*)&id.dst_addr)[1],
    //     ((u8*)&id.dst_addr)[2],
    //     ((u8*)&id.dst_addr)[3],
    //     ntohs(id.dst_port),

    //     id.protocol,

    //     ((u8*)&val.server_addr)[0],
    //     ((u8*)&val.server_addr)[1],
    //     ((u8*)&val.server_addr)[2],
    //     ((u8*)&val.server_addr)[3],
        
    //     index
    // );
}

void nf_init(host_time_t timestamp)
{       
    printf("Total flow capacity: %d\n", TOTAL_FLOW_NUM);

    *(u16*)SWITCH_INNER_MAC = htons(SHARED_SWITCH_INNER_MAC_HI16);
    *(u32*)(SWITCH_INNER_MAC+2) = htonl(SHARED_SWITCH_INNER_MAC_LO32);
    *(u16*)NF_INNER_MAC = htons(SHARED_NF_INNER_MAC_HI16);
    *(u32*)(NF_INNER_MAC+2) = htonl(SHARED_NF_INNER_MAC_LO32);

    inuse_head.l = inuse_head.r = &inuse_head;
    sw_head.l = sw_head.r = &sw_head;
    avail_head.l = avail_head.r = &avail_head;

    memset(flow_entry, 0, sizeof(flow_entry));
    memset(sw_cnt, 0, sizeof(sw_cnt));
    memset(sw_version, 0, sizeof(sw_version));
    

    for(flow_num_t i = 0; i < TOTAL_FLOW_NUM; i++) {
        flow_entry_t *entry = &flow_entry[i];
        if(i < SWITCH_FLOW_NUM) {
            entry->type = list_type::sw;
            entry->index_host = i;
            list_insert_before(&sw_head, entry);
            sw_entry[i] = entry;
        }
        else {
            entry->type = list_type::avail;
            list_insert_before(&avail_head, entry);
        }
    }
    
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

u8 next_version(u8 version) {
    return (version & 0xf0) | ((version + 1) & 0x0f);
}

u8 prev_version(u8 version) {
    return (version & 0xf0) | ((version - 1) & 0x0f);
}
// TODO
void send_update(flow_num_t index, queue_process_buf *queue)
{
    update_cnt ++;

    struct rte_mbuf *buf = queue->alloc();
    buf->data_len = sizeof(ethernet_t) + sizeof(metadata_t);
    buf->pkt_len = buf->data_len;

    hdr_t *hdr = rte_pktmbuf_mtod(buf, hdr_t *);
    // MAC address is useless between nf & switch

    // for counter, the update has two stage
    hdr->metadata.map = wait_set[index].new_flow->map; // match nothing
    hdr->metadata.old_version = wait_set[index].old_version;
    hdr->metadata.new_version = next_version(hdr->metadata.old_version);
    hdr->metadata.type = 6;
    hdr->metadata.main_flow_count = wait_set[index].is_closing;    

    hdr->metadata.index = htonl(index);

    hdr->metadata.checksum = 0;// clear to recalculate

    net_checksum_calculator sum;
    sum.add(&hdr->metadata, sizeof(hdr->metadata));
    
    hdr->metadata.checksum = sum.checksum();

    debug_printf("\nsend update\n");
    debug_printf("old map:\n");
    print_map(wait_set[index].old_flow->map, index);
    debug_printf("new map:\n");
    print_map(wait_set[index].new_flow->map, index);
    
    debug_printf("version %x -> %x\n", hdr->metadata.old_version, hdr->metadata.new_version);

    send_back(buf, queue);
}
// TODO
void try_add_update(flow_num_t wait_set_index, metadata_t &metadata, host_time_t timestamp, queue_process_buf *queue)
{
    flow_entry_t *old_entry = sw_entry[wait_set_index];
    flow_entry_t *new_entry;

    if(wait_set_size >= UPDATE_QUEUE_SIZE) return;

    if(!wait_set[wait_set_index].is_waiting && 
        (timestamp - wait_set[wait_set_index].last_req_time_host >= SWAP_TIME_US || 
        old_entry->map.id.protocol == 0)) {
        
        if(old_entry->map.id.protocol == 0) {
            new_entry = heavy_hitter_get(wait_set_index);
            if(new_entry == NULL) return;
        }
        else {
            if(list_empty(&avail_head)) {
                debug_printf("no rule for replacement\n");
                return;
            }
            new_entry = list_front(&avail_head);
            new_entry->map = (map_entry_t){};
            new_entry->index_host = old_entry->index_host;
            new_entry->timestamp_host = timestamp;
            new_entry->type = list_type::inuse;
            new_entry->is_waiting = true;
            list_move_to_back(&inuse_head, new_entry);
            // no id_map insertion
        }

        assert(old_entry->type == list_type::sw);

        wait_set[wait_set_index] = {new_entry, old_entry, 
#ifdef REJECT_TEST
                                    metadata.old_version ^ 0xA0, // make inplace version mismatch
#else
                                    metadata.old_version, 
#endif
                                    timestamp, timestamp, 
                                    true, old_entry->map.id.protocol != 0, NULL, NULL};// first, close the entry
            
        // map entry
        new_entry->is_waiting = 1;// locked, it will not be moved to list "avail" immediately
        old_entry->is_waiting = 1;

        // wait for response to merge the value on switch
        old_entry->map.val.counter = 0;

        if(old_entry->map.id.protocol != 0) {
            auto ret = id_map.insert(make_pair(old_entry->map.id, old_entry));
            if(!ret.second) {
                fprintf(stderr, "WARNING: (%x:%hu, %x:%hu, %d) already exists." ,
                    ntohl(old_entry->map.id.src_addr), ntohs(old_entry->map.id.src_port),
                    ntohl(old_entry->map.id.dst_addr), ntohs(old_entry->map.id.dst_port),
                    old_entry->map.id.protocol);
            }
        }
            
        //assert(ret.second);

        list_insert_before(&wait_set_head, &wait_set[wait_set_index]);// == push_back
        wait_set_size ++;
        wait_set_inc ++;
        send_update(wait_set_index, queue);
    }
}
//  TODO
void update_sw_count(hdr_t * hdr, host_time_t timestamp)
{
    flow_num_t index_host = ntohl(hdr->metadata.index);
    if(sw_entry[index_host]->is_waiting) return;
    if((hdr->metadata.old_version & 0x0f) != sw_version[index_host]){
        print_map(hdr->metadata.map, index_host);
        return;
    }

    switch_counter_t &old_cnt = sw_cnt[index_host];
    switch_counter_t new_cnt = hdr->metadata.main_flow_count;
    switch_counter_t diff = new_cnt - old_cnt;

    old_cnt = new_cnt;
    sw_entry[index_host]->map = hdr->metadata.map;// not only "id"
    heavy_hitter_count(index_host, sw_entry[index_host], diff, timestamp);
}

void process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    hdr_t* hdr = rte_pktmbuf_mtod(buf, hdr_t*);
    
    bool is_tcp = hdr->ip.protocol == TCP_PROTOCOL;
    bool is_forward = hdr->metadata.type == 4;
// heavy_hitter for main_flow
    update_sw_count(hdr, timestamp);

    flow_num_t index = ntohl(hdr->metadata.index);

    if(!sw_entry[index]->is_waiting && (hdr->metadata.old_version & 0x0f) != sw_version[index]) {
        fprintf(stderr, "packet info out of date, drop.\n");
        queue->drop(buf);
        return;
    } 
    
    flow_id_t flow_id;
    if(is_forward) 
        flow_id = {hdr->ip.src_addr, hdr->ip.dst_addr, 
                        hdr->L4_header.udp.src_port, hdr->L4_header.udp.dst_port, // the same as tcp
                        hdr->ip.protocol, (u8)0};
    else // 5 
        flow_id = {hdr->ip.dst_addr, hdr->ip.src_addr, 
                        hdr->L4_header.udp.dst_port, hdr->L4_header.udp.src_port, // the same as tcp
                        hdr->ip.protocol, (u8)0};

// allocate flow state for new flow    
    // things in map are in network byte order
    auto id_map_it = id_map.find(flow_id);
    flow_entry_t *entry;

    if(id_map_it == id_map.end()) {// a new flow
        if(!is_forward) {
            queue->drop(buf);
            return;
        }

        flow_num_t id_index_host;
#ifdef ONE_ENTRY_TEST
        id_index_host = 1;
#else
        id_index_host = get_index(flow_id);
#endif
        assert(id_index_host == index);

        if(list_empty(&avail_head)) {
            debug_printf("Warning: Too full to allocate an entry for a new flow, drop.\n");
            queue->drop(buf);
            return;
        }
        entry = list_front(&avail_head);
        
        entry->map = {flow_id, {0}};
        entry->index_host = id_index_host;
        entry->type = list_type::inuse;
        entry->is_waiting = 0;

        list_move_to_back(&inuse_head, entry);
        id_map.insert(make_pair(flow_id, entry));
    }
    else {
        entry = id_map_it->second;
    }
// refresh flow's timestamp
    entry->timestamp_host = timestamp;// host

    assert(entry->type == list_type::inuse || (entry->type == list_type::sw && entry->is_waiting));
// move to the tail of aging queue
    if(entry->type == list_type::inuse) {
        list_move_to_back(&inuse_head, entry);
    }

// heavy_hitter for this flow
    heavy_hitter_count(index, entry, 1, timestamp);

// count
    entry->map.val.counter++;

// try add update
    metadata_t &metadata = hdr->metadata;
    try_add_update(index, metadata, timestamp, queue);

// modify flieds in metadata
    net_checksum_calculator metadata_sum;
    metadata_sum.sub(&metadata.type);// default 2 bytes
    metadata.type -= 2;// 4->2, 5->3
    metadata.main_flow_count = 0;
    metadata_sum.add(&metadata.type);

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
    pkt_cnt++;
}

void ack_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    hdr_t* hdr = rte_pktmbuf_mtod(buf, hdr_t*);

    metadata_t &metadata = hdr->metadata;

    u8 nf_new_version = metadata.new_version;
    u8 nf_old_version = prev_version(metadata.new_version);
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
        debug_printf("Redundant ACK, drop.\n");
        return; // Redundant ACK
    }
    // mismatch
    if(wait_entry->old_version != nf_old_version || 
        (wait_entry->is_closing && metadata.main_flow_count != 1) ||
        (!wait_entry->is_closing && metadata.main_flow_count != 0)){
        queue->drop(buf);
        debug_printf("update packet info mismatch, drop.\n");
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
    wait_set_size --;
    wait_set_dec ++;

    if(update_flag == reject_flag) {// reject
        if(entry_sw->map.id.protocol != 0) {
            auto erase_res = id_map.erase(entry_sw->map.id);
            assert(erase_res);
        }
        if(entry_nf->map.id.protocol == 0) {
            entry_nf->type = list_type::avail;
            list_move_to_front(&avail_head, entry_nf);
        }
    }
    else if(update_flag == accept_flag) { // accept
        if(entry_sw->map.id.protocol != 0) {
            entry_sw->timestamp_host = timestamp;
            entry_sw->type = list_type::inuse;
            list_move_to_back(&inuse_head, entry_sw);
        }
        else {
            entry_sw->type = list_type::avail;
            list_move_to_back(&avail_head, entry_sw);
        }
            
        entry_nf->type = list_type::sw;
        list_move_to_back(&sw_head, entry_nf);

        if(entry_nf->map.id.protocol != 0) {
            auto erase_res = id_map.erase(entry_nf->map.id);
            assert(erase_res); 
        }   
        else {
            entry_sw->map.val.counter += metadata.map.val.counter; // merge the state
        }

        sw_entry[index] = entry_nf;
        sw_version[index] = nf_new_version & 0x0f;
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

        list_move_to_front(&avail_head, entry);
        entry->type = list_type::avail;
        auto erase_res = id_map.erase(entry->map.id);
        assert(erase_res == 1); 
        memset(&entry->map.id, 0, sizeof(entry->map.id));
    }
    // for debug
    static host_time_t last_timestamp = 0;
    if(timestamp - last_timestamp < 1000000) return; 
    printf("process f/b: %.2lf mpps\nupdate: %.2lf kpps\n", 
        1.0*pkt_cnt/(timestamp - last_timestamp), 
        1e3*update_cnt/(timestamp - last_timestamp));
    update_cnt = 0;
    pkt_cnt = 0;
    last_timestamp = timestamp;    


    debug_printf("\n");
    debug_printf("old\n");
    flow_entry_t *entry = list_front(&inuse_head);
    int cnt = 0;
    while(entry != &inuse_head) {
        print_map(entry->map, entry->index_host);
        cnt++;
        entry = entry->r;
    }
    debug_printf("new\n");
    printf("%d active flows\n", cnt);
    printf("update set size: %d, inc: %d, dec: %d\n\n", wait_set_size, wait_set_inc, wait_set_dec);
    wait_set_inc = 0;
    wait_set_dec = 0;
}

void report_wait_time_too_long()
{
    fprintf(stderr, "Wait time too long!\n\
You may reset the values of time in C++ codes to avoid this happen.\n");
    exit(0);
}

void nf_update(host_time_t timestamp, queue_process_buf *queue)
{
    for(int i = 0; i < UPDATE_TX_LIMIT && !list_empty(&wait_set_head); i++)
    {
        wait_entry_t *entry = list_front(&wait_set_head);
        if(timestamp - entry->last_req_time_host <= WAIT_TIME_US) break;

        // prevent the worst case: switch should response in time no matter it is an accept or reject
        if(timestamp - entry->first_req_time_host > AGING_TIME_US) report_wait_time_too_long();

        entry->last_req_time_host = timestamp;

        send_update(entry->new_flow->index_host, queue);// == (entry - &wait_set_head)
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

    // if(hdr->metadata.map.id.src_addr == 0) {
    //     fprintf(stderr, "Error: Switch's entry is empty.\n");
    //     queue->drop(buf); 
    //     return;
    // }

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
    else 
        process(timestamp, buf, queue);
}

int main(int argc, char **argv)
{
    dpdk_main(argc, argv);
    return 0;
}