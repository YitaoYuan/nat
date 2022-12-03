#include "type.h"

template<typename COUNTER_T, typename ID_T>
struct heavy_hitter_entry_t{
    COUNTER_T cnt;
    ID_T id;
};

template<typename COUNTER_T, typename ID_T, size_t HEAVY_HITTER_SIZE, size_t EPOCH_CNT_MAX, host_time_t EPOCH_TIME_MAX>
struct heavy_hitter_t{
    heavy_hitter_entry_t<COUNTER_T, ID_T> entry[HEAVY_HITTER_SIZE];
    // entry[0].cnt is max, entry[HEAVY_HITTER_SIZE-1].cnt is min
    size_t size;
    COUNTER_T this_epoch_cnt;
    host_time_t pre_ts;

    void init(host_time_t ts) {
        size = 0;
        this_epoch_cnt = 0;
        pre_ts = ts;
        memset(entry, 0, sizeof(entry));
    }
    void update_epoch(u32 d_epoch) {
        if(d_epoch >= 32) {
            for(size_t i = 0; i < size; i++) 
                entry[i].cnt = 0;
        }
        else {
            for(size_t i = 0; i < size; i++) 
                entry[i].cnt >>= d_epoch;
        }
        for(size_t i = 0; i < size; i++) 
            if(entry[i].cnt == 0) 
                size = i;
    }
    void count(ID_T id, COUNTER_T cnt, host_time_t ts) {
        if(cnt == 0) return;
        
        if(ts - pre_ts >= EPOCH_TIME_MAX) {
            update_epoch((ts - pre_ts) / EPOCH_TIME_MAX);
            pre_ts += (ts - pre_ts) / EPOCH_TIME_MAX * EPOCH_TIME_MAX;
            this_epoch_cnt = 0;
        }
        else if(this_epoch_cnt >= EPOCH_CNT_MAX){
            update_epoch(1);
            pre_ts = ts;
            this_epoch_cnt = 0;
        }
            
        size_t i;
        for(i = 0; i < size; i++) if(entry[i].id == id) break;
        if(i >= size) {
            if(i == HEAVY_HITTER_SIZE) i--;//满了就用最后一个
            else size++;
            entry[i].id = id;
        }
        entry[i].cnt += cnt;
        this_epoch_cnt += cnt;
        // re-sort
        for(i = i-1; i < size; i--) if(entry[i].cnt < entry[i+1].cnt) swap(entry[i], entry[i+1]);
    }
};