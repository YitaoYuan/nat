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
#include "nat_hdr.h"
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

volatile bool clear_flag;
unordered_map<flow_id_t, flow_val_t, my_hash<flow_id_t, SHARED_SWITCH_CRC_POLY>, mem_equal<flow_id_t>>fmap;
unordered_map<flow_val_t, flow_val_t, my_hash<flow_val_t, SHARED_SWITCH_CRC_POLY>, mem_equal<flow_val_t>>bmap;

void nf_init(host_time_t timestamp)
{       
    
}

void forward_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    //fprintf(stderr, "fw\n");
    hdr_t* hdr = rte_pktmbuf_mtod(buf, hdr_t*);
    *(u16*)hdr->ethernet.dst_addr = htons(W3_HI16);
    *(u32*)(hdr->ethernet.dst_addr+2) = htonl(W3_LO32);
    *(u16*)hdr->ethernet.src_addr = htons(P3_HI16);
    *(u32*)(hdr->ethernet.src_addr+2) = htonl(P3_LO32);

    flow_id_t fid = (flow_id_t){hdr->ip.src_addr, hdr->ip.dst_addr, hdr->udp.src_port, hdr->udp.dst_port, hdr->ip.protocol, 0};

    auto it = fmap.insert(make_pair(fid, (flow_val_t){0, 0}));
    if(it.second) {
        flow_val_t fval = (flow_val_t){hdr->ip.src_addr ^ 0xff000000, hdr->udp.src_port};
        it.first->second = fval;
        bmap[fval] = (flow_val_t){hdr->ip.src_addr, hdr->udp.src_port};
    }
    hdr->ip.src_addr = it.first->second.wan_addr;
    hdr->udp.src_port = it.first->second.wan_port;
    queue->send(buf);
}

void backward_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    //fprintf(stderr, "back\n");
    hdr_t* hdr = rte_pktmbuf_mtod(buf, hdr_t*);
    *(u16*)hdr->ethernet.dst_addr = htons(W1_HI16);
    *(u32*)(hdr->ethernet.dst_addr+2) = htonl(W1_LO32);
    *(u16*)hdr->ethernet.src_addr = htons(P1_HI16);
    *(u32*)(hdr->ethernet.src_addr+2) = htonl(P1_LO32);

    auto it = bmap.find((flow_val_t){hdr->ip.dst_addr, hdr->udp.dst_port});
    if(it == bmap.end()) {
        queue->drop(buf);
        return;
    }

    hdr->ip.src_addr = it->second.wan_addr;// lan_addr
    hdr->udp.src_port = it->second.wan_port;// lan_port
    queue->send(buf);
}

void nf_aging(host_time_t timestamp)
{
    if(clear_flag) {
        printf("clear\n");
        fmap.clear();
        bmap.clear();
        clear_flag = 0;
    }
}

void nf_update(host_time_t timestamp, queue_process_buf *queue)
{
    
}

void nf_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue)
{
    //fprintf(stderr, "rcv\n");
    if(buf->pkt_len != buf->data_len) {queue->drop(buf); return;}

    if(buf->pkt_len < sizeof(hdr_t)) {queue->drop(buf); return;}

    hdr_t* hdr = rte_pktmbuf_mtod(buf, hdr_t*);

    if(*(u32*)(hdr->ethernet.src_addr+2) == htonl(W1_LO32))
        forward_process(timestamp, buf, queue);
    else 
        backward_process(timestamp, buf, queue);
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