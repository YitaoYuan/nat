#include "type.h"

template<typename COUNTER_T, typename ID_T>
struct heavy_hitter_entry_t{
    COUNTER_T cnt;
    ID_T id;
};

template<typename COUNTER_T, typename ID_T, u32 HEAVY_HITTER_SIZE, u32 HEAVY_HITTER_REBOOT_THRESHOLD>
struct heavy_hitter_t{
    heavy_hitter_entry_t<COUNTER_T, ID_T> entry[HEAVY_HITTER_SIZE];
    // entry[0].cnt is max, entry[HEAVY_HITTER_SIZE-1].cnt is min
    int size, total_cnt;
    void init() {
        size = 0;
        total_cnt = 0;
        memset(entry, 0, sizeof(entry));
    }
    void count(ID_T id) {
        if(total_cnt == HEAVY_HITTER_REBOOT_THRESHOLD) init();
        int i;
        for(i = 0; i < size; i++) if(entry[i].id == id) break;
        if(i >= size) {
            if(i == HEAVY_HITTER_SIZE) i--;//满了就用最后一个
            else size++;
            entry[i].id = id;
        }
        entry[i].cnt++;
        total_cnt++;
        // re-sort
        for(i = i-1; i >= 0; i--) if(entry[i].cnt < entry[i+1].cnt) swap(entry[i], entry[i+1]);
    }
};