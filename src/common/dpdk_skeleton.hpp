void nf_init(host_time_t timestamp);
void nf_update(host_time_t timestamp, queue_process_buf *queue);
void nf_process(host_time_t timestamp, struct rte_mbuf *buf, queue_process_buf *queue);
void nf_aging(host_time_t timestamp);

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

    for(int i = 0; ; i++) {
        if(unlikely((i & 0xf) == 0)) {
            nf_aging(get_mytime());
            nf_update(get_mytime(), &queue);
        }

        struct rte_mbuf *buf = queue.receive();
        if(buf != NULL)
            nf_process(get_mytime(), buf, &queue);

//         if(queue.total_rx_nb + queue.total_alloc_nb != queue.total_tx_nb + queue.total_drop_nb) {
//             fprintf(stderr, "rx: %u, tx: %u, drop: %u, alloc: %u\n", 
//                 queue.total_rx_nb, queue.total_tx_nb, queue.total_drop_nb, queue.total_alloc_nb);
//             fprintf(stderr, "WARNING: total_rx_nb + total_alloc_nb != total_tx_nb + total_drop_nb. \n\
// Either some packets are not recycled or some external packets send/droped by this queue.\n\
// You can ignore this warning if you have cross-queue packets.\n");
//         }
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
// static const struct rte_eth_conf port_conf_default = {
//     .rxmode = {
//         .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
//     },
// };

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    //struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.max_rx_pkt_len = RTE_ETHER_MAX_LEN;
    
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

void dpdk_init(char *nic_name, uint16_t *portid, struct rte_mempool **mbuf_pool)
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

int dpdk_main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("Usage: test <interface_name>\n");
        return 0;
    }
    char *ifname = argv[1];
    uint16_t portid;
    struct rte_mempool *mbuf_pool;
    dpdk_init(ifname, &portid, &mbuf_pool);
    lcore_main(portid, mbuf_pool);
    /* clean up the EAL */
    rte_eal_cleanup();
    return 0;
}