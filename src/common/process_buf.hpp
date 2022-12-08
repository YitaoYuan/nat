#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

class queue_process_buf {
private:
    struct rte_mempool *mbuf_pool;
    const uint16_t portid;
    const uint16_t queueid;
    const uint16_t rx_size;
    const uint16_t tx_size;
    uint16_t rx_nb;
    uint16_t tx_nb;
    uint16_t rx_iter;
    uint16_t flush_timer;
    struct rte_mbuf **rx_bufs;
    struct rte_mbuf **tx_bufs;
public:
    uint32_t total_rx_nb;
    uint32_t total_tx_nb;
    uint32_t total_drop_nb;
    uint32_t total_alloc_nb;
    queue_process_buf(struct rte_mempool *_mbuf_pool, uint16_t _portid, 
        uint16_t _queueid, uint16_t _rx_size, uint16_t _tx_size) 
        : mbuf_pool(_mbuf_pool), portid(_portid), queueid(_queueid), rx_size(_rx_size), tx_size(_tx_size) 
    {
        rx_nb = tx_nb = rx_iter = flush_timer = 0;
        rx_bufs = (struct rte_mbuf **)calloc(rx_size, sizeof(struct rte_mbuf *));
        tx_bufs = (struct rte_mbuf **)calloc(tx_size, sizeof(struct rte_mbuf *));
        total_rx_nb = total_tx_nb = total_drop_nb = total_alloc_nb = 0;
    }

    void flush() {
        uint16_t complete_nb = rte_eth_tx_burst(portid, queueid, tx_bufs, tx_nb);
        while(unlikely(complete_nb < tx_nb)) {
            complete_nb += rte_eth_tx_burst(portid, queueid, tx_bufs + complete_nb, tx_nb - complete_nb);
        }
        flush_timer = 0;
        tx_nb = 0;
    }

    void check_flush_timer() {
        if(flush_timer == (tx_size + tx_size/2)) flush();
        flush_timer ++;
    }

    struct rte_mbuf * receive() {
#ifdef DEBUG
        if((total_rx_nb & 0xfffff) == 0xfffff) {
            fprintf(stderr, "rx: %u, tx: %u, drop: %u, alloc: %u\n", 
                total_rx_nb, total_tx_nb, total_drop_nb, total_alloc_nb);
        }
#endif
        check_flush_timer();
        if(unlikely(rx_iter == rx_nb)) {
            rx_iter = 0;
            rx_nb = rte_eth_rx_burst(portid, queueid, rx_bufs, rx_size);
            if(rx_nb == 0) return NULL;
        }
        total_rx_nb ++;
        return rx_bufs[rx_iter ++];
    }

    void send(struct rte_mbuf * buf) {
        total_tx_nb ++;

        tx_bufs[tx_nb ++] = buf;
        // if all the sending packet is receive from the same queue, usually there is "tx_nb < tx_size"
        if(tx_nb == tx_size) flush();
    }

    struct rte_mbuf * alloc() {
        total_alloc_nb ++;

        check_flush_timer();
        return rte_pktmbuf_alloc(mbuf_pool);
    }

    void drop(struct rte_mbuf * buf) {
        total_drop_nb ++;

        rte_pktmbuf_free(buf);
    }

};