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
#include "lb_hdr.h"
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

struct mac_t {
    u8 dmac[6];// ether dmac comes first
    u8 smac[6];
};

volatile bool clear_flag;
unordered_map<flow_id_t, map_entry_t*, my_hash<flow_id_t, SHARED_SWITCH_CRC_POLY>, mem_equal<flow_id_t>>fmap;
unordered_map<ip_addr_t, ip_addr_t>vipmap;
unordered_map<ip_addr_t, mac_t>macmap;
map_entry_t head;
my_hash<flow_id_t, SHARED_SWITCH_CRC_POLY>flow_hash;

// uint64_t pkt_cnt;
// uint64_t pre_cnt, checkpoint;
uint64_t pre_ts;
uint64_t f_cnt, b_cnt;

 
void nf_init(host_time_t timestamp)
{       
    vipmap[htonl(0xC0A80101)] = htonl(0xC0A802FE);
    vipmap[htonl(0xC0A80102)] = htonl(0xC0A802FE);
    mac_t *mac;
    mac = &macmap[htonl(0xC0A80101)];
    *(u16*)mac->smac = htons(P1_HI16);
    *(u32*)(mac->smac+2) = htonl(P1_LO32);
    *(u16*)mac->dmac = htons(W1_HI16);
    *(u32*)(mac->dmac+2) = htonl(W1_LO32);

    mac = &macmap[htonl(0xC0A80102)];
    *(u16*)mac->smac = htons(P2_HI16);
    *(u32*)(mac->smac+2) = htonl(P2_LO32);
    *(u16*)mac->dmac = htons(W2_HI16);
    *(u32*)(mac->dmac+2) = htonl(W2_LO32); 

    pre_ts = timestamp;

    head.l = head.r = &head;
}


void forward_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    //fprintf(stderr, "fw\n");
    hdr_t* hdr = rte_pktmbuf_mtod(buf, hdr_t*);

    flow_id_t fid = (flow_id_t){hdr->ip.src_addr, hdr->ip.dst_addr, hdr->udp.src_port, hdr->udp.dst_port, hdr->ip.protocol, 0};
    
    auto it = fmap.insert(make_pair(fid, (map_entry_t*)NULL));
    if(it.second) {
        map_entry_t *entry = (map_entry_t *)malloc(sizeof(map_entry_t));
        entry->id = fid;

        int hash_val = flow_hash(fid) & 1;
        ip_addr_t dst_ip = htonl(0xC0A80101 + hash_val);
        entry->val = (flow_val_t){dst_ip};

        list_insert_before(&head, entry);
       
        it.first->second = entry;
    }
    map_entry_t *entry = it.first->second;

    entry->ts = timestamp;
    list_move_to_back(&head, entry);

    hdr->ip.dst_addr = entry->val.server_addr;
    
    memcpy(&hdr->ethernet, &macmap[hdr->ip.dst_addr], sizeof(struct mac_t));
    queue->send(buf);
    f_cnt ++;
}

void nf_aging(host_time_t timestamp)
{
    while(!list_empty(&head)) {
        map_entry_t *entry = list_front(&head);
        if(timestamp-entry->ts < 10000000) break;
        fmap.erase(entry->id);
        list_erase(entry);
        free(entry);
    }
    if(timestamp - pre_ts > 1000000) {
        fprintf(stderr, "f:%ld b:%ld\n", f_cnt, b_cnt);
        f_cnt = b_cnt = 0;

        pre_ts = timestamp;
        int flowcnt = 0;
        for(map_entry_t *entry = head.r; entry != &head; entry = entry->r)
            flowcnt ++;
        fprintf(stderr, "%d\n", flowcnt);
    }
    // if(clear_flag) {
    //     printf("clear\n");
    //     fmap.clear();// only clear fmap
    //     clear_flag = 0;
    // }
}

void nf_update(host_time_t timestamp, queue_process_buf *queue)
{
    
}

void nf_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    //fprintf(stderr, "rcv\n");
    if(buf->pkt_len != buf->data_len) {queue->drop(buf); return;}

    if(buf->pkt_len < sizeof(hdr_t)) {queue->drop(buf); return;}

    forward_process(timestamp, buf, queue);
}

void 
handler(int signum)
{
    if(signum == SIGTSTP)
        clear_flag = 1;
}

int main(int argc, char **argv)
{
    printf("use CTRL+Z to clear tables\n");
    signal(SIGTSTP, handler);
    dpdk_main(argc, argv);
    return 0;
}