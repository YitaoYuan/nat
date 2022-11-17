#include "mb_policy.hpp"

void delete_mb_policies(int n, mb_policy_t *plcs) {
	for (int i = 0; i < n; i ++) {
		free(plcs[i].vlan_id);
		free(plcs[i].off);
	}
	free(plcs);
}
