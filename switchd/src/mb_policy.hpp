#pragma once
#include <stdint.h>
#include <malloc.h>

typedef struct mb_policy_s {
public:
    uint64_t token;
    int n_vlan_id;
    int n_off;
    uint32_t msk;
    uint16_t* vlan_id;
    uint32_t* off;
}mb_policy_t;

void delete_mb_policies(int n, mb_policy_t *plcs);
