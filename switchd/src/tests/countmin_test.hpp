#pragma once

#include "../vtest.hpp"
#include "../mb_policy.hpp"
#include "../drv_service.hpp"
#include "global_config.hpp"

using grpc::Server;
using grpc::ServerBuilder;
using namespace std;

// #define PRINT_TABLE_INFO

#define MAX_TENANT 512
#define MAX_GROUP_SIZE 32

#define CUSTOM_PACKET_ID 666

/*char macs[][100] = {"b8:59:9f:1d:04:f2",
                    "b8:59:9f:0b:30:72",
                    "98:03:9b:03:46:50",
                    "b8:59:9f:02:0d:14",
                    "b8:59:9f:b0:2d:50",
                    "b8:59:9f:b0:2b:b0",
                    "b8:59:9f:b0:2b:b8",
                    "b8:59:9f:b0:2d:18",
                    "b8:59:9f:b0:2d:58",
                    "0c:42:a1:7a:b6:69",
                    "0c:42:a1:7a:ca:29",
                    "0c:42:a1:7a:b6:68",
                    "0c:42:a1:7a:ca:28"};
uint64_t ports[] = {56, 48, 40, 32, 24, 16, 8, 0, 4, 136, 128, 44, 36};*/
static char macs[][100] = {"10:70:fd:19:00:95",
                           "10:70:fd:2f:d8:51",
                           "10:70:fd:2f:e4:41",
                           "10:70:fd:2f:d4:21"}; // worker 1-4
static uint64_t ports[] = {180, 164, 148, 132};
static uint64_t sw_port = 132;

static int batch_size = 32;

class CountMinTest : public VTest {
public:

    CountMinTest(GlobalConfig &global_cfg)
        : VTest(global_cfg),
          drv_server_addr(global_cfg.drv_service_addr),
          drv_service(global_cfg, this),
          logger(global_cfg.logger) {
        n_tenant = 0;
    }

    /* init l2_route table */
    int init_fwd_table() {
        bf_status_t status;
        const bfrt::BfRtTable *l2_route = nullptr;
        status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.l2_route",
                                                &l2_route);
        ASSERT_STATUS("Cannot get table : l2_route");

#ifdef PRINT_TABLE_INFO
        print_table_info(l2_route);
#endif

        unique_ptr<bfrt::BfRtTableKey> key;
        unique_ptr<bfrt::BfRtTableData> data;
        bf_rt_id_t action_id;
        bf_rt_id_t key_field_id;
        bf_rt_id_t data_field_id;
        uint8_t mac_val[6];

        status = l2_route->keyFieldIdGet("hdr.ethernet.dst_addr", &key_field_id);
        status = l2_route->actionIdGet("SwitchIngress.l2_forward", &action_id);
        status = l2_route->dataFieldIdGet("port", action_id, &data_field_id);
        status = l2_route->keyAllocate(&key);
        status = l2_route->dataAllocate(action_id, &data);

        for (size_t i = 0; i < sizeof(macs) / sizeof(macs[0]); i ++) {
            str2mac(macs[i], mac_val);
            status = key->setValue(key_field_id, mac_val, 6);
            status = data->setValue(data_field_id, ports[i]);
            status = l2_route->tableEntryAdd(*sess, dev_tgt, *key, *data);
        }

        status = sess->sessionCompleteOperations();
        logger.info("Successfully initialized l2_route table.");
        return 0;
    }

    int init_check_app_table() {
        bf_status_t status;
        const bfrt::BfRtTable *ckapp = nullptr;
        status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.check_app",
                                                &ckapp);
        ASSERT_STATUS("Cannot get table : check_app");

#ifdef PRINT_TABLE_INFO
        print_table_info(ckapp);
#endif

        unique_ptr<bfrt::BfRtTableKey> key;
        unique_ptr<bfrt::BfRtTableData> data;
        bf_rt_id_t action_id;
        bf_rt_id_t key_field_id;
        bf_rt_id_t data_field_id;

        status = ckapp->keyFieldIdGet("hdr.ipv4.identification", &key_field_id);
        status = ckapp->actionIdGet("SwitchIngress.verify_app", &action_id);
        status = ckapp->dataFieldIdGet("vrf", action_id, &data_field_id);
        status = ckapp->keyAllocate(&key);
        status = ckapp->dataAllocate(action_id, &data);

        status = key->setValue(key_field_id, (uint64_t)CUSTOM_PACKET_ID);
        status = data->setValue(data_field_id, (uint64_t)1);
        status = ckapp->tableEntryAdd(*sess, dev_tgt, *key, *data);

        status = sess->sessionCompleteOperations();
        logger.info("Successfully initialized check_app table.");
        return 0;
    }

    int add_get_tid_table(int n_tenant, mb_policy_t* plcs) {
        bf_status_t status;
        const bfrt::BfRtTable *tid_table = nullptr;
        status = bfrtInfo->bfrtTableFromNameGet(
                        "SwitchIngress.get_tid",
                        &tid_table);
                        
#ifdef PRINT_TABLE_INFO
        print_table_info(tid_table);
#endif

        bf_rt_id_t tid_key_id;
        bf_rt_id_t tid_act_id;
        bf_rt_id_t tid_tid_id;
        bf_rt_id_t tid_mid_id;
        bf_rt_id_t tid_rec_id;
        unique_ptr<bfrt::BfRtTableKey> key;
        unique_ptr<bfrt::BfRtTableData> data;

        status = tid_table->keyFieldIdGet("hdr.vlan_tag.vid", &tid_key_id);
        status = tid_table->actionIdGet("SwitchIngress.set_tid", &tid_act_id);
        status = tid_table->dataFieldIdGet("tid", tid_act_id, &tid_tid_id);
        status = tid_table->dataFieldIdGet("mid", tid_act_id, &tid_mid_id);
        status = tid_table->dataFieldIdGet("rec", tid_act_id, &tid_rec_id);

        // build get_tid table
        status = tid_table->keyAllocate(&key);
        status = tid_table->dataAllocate(tid_act_id, &data);

        // status = sess->beginTransaction(true);
        for (int t = 0; t < n_tenant; t ++) {
            // action_mem_id starts from 1
            for (int i = 0; i < plcs[t].n_vlan_id; i ++) {
                
                status = key->setValue(tid_key_id, (uint64_t)plcs[t].vlan_id[i]);
                status = data->setValue(tid_tid_id, (uint64_t)t);
                status = data->setValue(tid_mid_id, (uint64_t)machineid);
                status = data->setValue(tid_rec_id, (uint64_t)1);
                status = tid_table->tableEntryAdd(*sess, dev_tgt, *key, *data);
                ASSERT_STATUS("error adding entry to tid_table");
            }
        }
        // status = sess->verifyTransaction();
        // status = sess->commitTransaction(true);
        status = sess->sessionCompleteOperations();
        return 0;
    }

    int init_fwd_to_sw_table() {
        bf_status_t status;
        const bfrt::BfRtTable *fsw_table = nullptr;
        status = bfrtInfo->bfrtTableFromNameGet(
                        "SwitchIngress.forward_to_software",
                        &fsw_table);

#ifdef PRINT_TABLE_INFO
        print_table_info(fsw_table);
#endif

        bf_rt_id_t fsw_act_id;
        bf_rt_id_t fsw_pot_id;
        unique_ptr<bfrt::BfRtTableKey> key;
        unique_ptr<bfrt::BfRtTableData> data;

        status = fsw_table->actionIdGet("SwitchIngress.l2_forward", &fsw_act_id);
        status = fsw_table->dataFieldIdGet("port", fsw_act_id, &fsw_pot_id);

        // build forward_to_software table
        status = fsw_table->keyAllocate(&key);
        status = fsw_table->dataAllocate(fsw_act_id, &data);
        status = data->setValue(fsw_pot_id, (uint64_t)sw_port);
        status = fsw_table->tableDefaultEntrySet(*sess, dev_tgt, *data);
        ASSERT_STATUS("error setting default entry of fsw");
        return 0;
    }

    int add_tenant_info_table(int table_id, int n_tenant, mb_policy_t* plcs) {
        bf_status_t status;
        char table_name[100];
        const bfrt::BfRtTable *ma_table = nullptr;
        const bfrt::BfRtTable *action_sel = nullptr;
        const bfrt::BfRtTable *action_prof = nullptr;
        sprintf(table_name, "SwitchIngress.getindex_%d.tenant_info", table_id);
        status = bfrtInfo->bfrtTableFromNameGet(table_name,
                                                &ma_table);
        sprintf(table_name, "SwitchIngress.getindex_%d.block_selector", table_id);
        status = bfrtInfo->bfrtTableFromNameGet(table_name,
                                                &action_sel);
        sprintf(table_name, "SwitchIngress.getindex_%d.block_selector_ap", table_id);
        status = bfrtInfo->bfrtTableFromNameGet(table_name,
                                                &action_prof);
        
#ifdef PRINT_TABLE_INFO
        print_table_info(ma_table);
        print_table_info(action_sel);
        print_table_info(action_prof);
#endif

        unique_ptr<bfrt::BfRtTableKey> key;
        unique_ptr<bfrt::BfRtTableData> data;
        bf_rt_id_t ma_key_id;
        bf_rt_id_t ma_mem_id;
        bf_rt_id_t ma_sel_id;
        bf_rt_id_t sel_grp_id;
        bf_rt_id_t sel_mem_id;
        bf_rt_id_t sel_sts_id;
        bf_rt_id_t sel_siz_id;
        bf_rt_id_t prof_mem_id;
        bf_rt_id_t prof_act_id;
        // bf_rt_id_t prof_tid_id;
        bf_rt_id_t prof_off_id;
        bf_rt_id_t prof_msk_id;
        
        status = ma_table->keyFieldIdGet("vlan_id", &ma_key_id);
        status = ma_table->dataFieldIdGet("$ACTION_MEMBER_ID", &ma_mem_id);
        status = ma_table->dataFieldIdGet("$SELECTOR_GROUP_ID", &ma_sel_id);
        status = action_sel->keyFieldIdGet("$SELECTOR_GROUP_ID", &sel_grp_id);
        status = action_sel->dataFieldIdGet("$ACTION_MEMBER_ID", &sel_mem_id);
        status = action_sel->dataFieldIdGet("$ACTION_MEMBER_STATUS", &sel_sts_id);
        status = action_sel->dataFieldIdGet("$MAX_GROUP_SIZE", &sel_siz_id);
        status = action_prof->keyFieldIdGet("$ACTION_MEMBER_ID", &prof_mem_id);
        char act_name[100];
        sprintf(act_name, "SwitchIngress.getindex_%d.get_index", table_id);
        status = action_prof->actionIdGet(act_name, &prof_act_id);
        // status = action_prof->dataFieldIdGet("tenant_id", prof_act_id, &prof_tid_id);
        status = action_prof->dataFieldIdGet("tenant_offset", prof_act_id, &prof_off_id);
        status = action_prof->dataFieldIdGet("tenant_mask", prof_act_id, &prof_msk_id);

        int total_mem = 0;

        // build action profile table
        status = action_prof->keyAllocate(&key);
        status = action_prof->dataAllocate(prof_act_id, &data);
        
        for (int t = 0; t < n_tenant; t ++) {
            // action_mem_id starts from 1
            for (int i = 0; i < plcs[t].n_off; i ++) {
                status = key->setValue(prof_mem_id, (uint64_t)(++total_mem));
                // status = data->setValue(prof_tid_id, (uint64_t)t);
                status = data->setValue(prof_off_id, (uint64_t)plcs[t].off[i]);
                status = data->setValue(prof_msk_id, (uint64_t)plcs[t].msk);
                status = action_prof->tableEntryAdd(*sess, dev_tgt, *key, *data);
                ASSERT_STATUS("error adding entry to action_prof");
            }
        }

        // build action selector table
        vector<bf_rt_id_t> mems;
        vector<bool> stss;
        total_mem = 0;
        status = action_sel->keyAllocate(&key);
        status = action_sel->dataAllocate(&data);
        for (int t = 0; t < n_tenant; t ++) {
            // selector_group_id starts from 1
            status = key->setValue(sel_grp_id, (uint64_t)(t+1));
            
            for (int i = 0; i < plcs[t].n_off; i ++) {
                mems.push_back(++total_mem);
                stss.push_back(true);
            }
            status = data->setValue(sel_mem_id, mems);
            status = data->setValue(sel_sts_id, stss);
            status = data->setValue(sel_siz_id, (uint64_t)plcs[t].n_off);
            status = action_sel->tableEntryAdd(*sess, dev_tgt, *key, *data);

            mems.clear();
            stss.clear();
        }

        // build tenant_info table
        status = ma_table->keyAllocate(&key);
        status = ma_table->dataAllocate(&data);
        for (int t = 0; t < n_tenant; t ++) {
            for (int i = 0; i < plcs[t].n_vlan_id; i ++) {
                status = key->setValue(ma_key_id, (uint64_t)plcs[t].vlan_id[i]);
                // status = data->setValue(ma_mem_id, (uint64_t)0);
                status = data->setValue(ma_sel_id, (uint64_t)(t+1));
                    // this will turn down field ma_mem_id
                status = ma_table->tableEntryAdd(*sess, dev_tgt, *key, *data);
                ASSERT_STATUS("error adding entry to ma_table");
            }
        }
        sess->sessionCompleteOperations();
        return 0;
    }

    int clear_register(int table_id) {
        bf_status_t status;
        char table_name[100];
        const bfrt::BfRtTable *reg = nullptr;
        sprintf(table_name, "SwitchIngress.cm_%d.cm_table", table_id);
        status = bfrtInfo->bfrtTableFromNameGet(table_name,
                                                &reg);
        
        unique_ptr<bfrt::BfRtTableKey> key;
        unique_ptr<bfrt::BfRtTableData> data;
        bf_rt_id_t key_field_id;
        bf_rt_id_t data_field_id;
        status = reg->keyFieldIdGet("$REGISTER_INDEX", &key_field_id);
        char df_name[100];
        sprintf(df_name, "SwitchIngress.cm_%d.cm_table.f1", table_id);
        status = reg->dataFieldIdGet(df_name, &data_field_id);
        status = reg->keyAllocate(&key);
        status = reg->dataAllocate(&data);

        uint8_t data_buf[4];
        memset(data_buf, 0, sizeof(data_buf));
        status = data->setValue(data_field_id, data_buf, 4);

        for (int i = 0; i < reg_size; i += batch_size) {
            status = sess->beginBatch();
            for (int j = i; j < i + batch_size && j < reg_size; j ++) {
                status = key->setValue(key_field_id, j);
                status = reg->tableEntryMod(*sess, dev_tgt, *key, *data);
            }
            status = sess->endBatch(false);
        }
        return 0;
    }

    int init_reg_size() {
        bf_status_t status;
        char table_name[100];
        const bfrt::BfRtTable *reg = nullptr;
        sprintf(table_name, "SwitchIngress.cm_%d.cm_table", 1);
        status = bfrtInfo->bfrtTableFromNameGet(table_name,
                                                &reg);
        
#ifdef PRINT_TABLE_INFO
        print_table_info(reg);
#endif
        status = reg->tableSizeGet(*sess, dev_tgt, (size_t *)&reg_size);
        ASSERT_STATUS("get reg_size failed");
        return 0;
    }

    int record_register(int table_id, int32_t *reg_data) {
        bf_status_t status;
        const bfrt::BfRtTable::BfRtTableGetFlag flag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_HW;
        char table_name[100];
        const bfrt::BfRtTable *reg = nullptr;
        sprintf(table_name, "SwitchIngress.cm_%d.cm_table", table_id);
        status = bfrtInfo->bfrtTableFromNameGet(table_name,
                                                &reg);

        unique_ptr<bfrt::BfRtTableKey> key;
        unique_ptr<bfrt::BfRtTableData> data;
        bf_rt_id_t key_field_id;
        bf_rt_id_t data_field_id;
        status = reg->keyFieldIdGet("$REGISTER_INDEX", &key_field_id);
        char df_name[100];
        sprintf(df_name, "SwitchIngress.cm_%d.cm_table.f1", table_id);
        status = reg->dataFieldIdGet(df_name, &data_field_id);
        status = reg->keyAllocate(&key);
        status = reg->dataAllocate(&data);

        vector<uint64_t> data_buf;
        data_buf.reserve(batch_size * 2);

        for (int i = 0; i < reg_size; i += batch_size) {
            status = sess->beginBatch();
            for (int j = i; j < i + batch_size && j < reg_size; j ++) {
                status = key->setValue(key_field_id, j);
                status = reg->tableEntryGet(*sess, dev_tgt, *key, flag, data.get());
            }
            status = sess->endBatch(false);
        }
        status = sess->sessionCompleteOperations();
        status = data->getValue(data_field_id, &data_buf);
        for (int j = 0; j < reg_size; j ++) {
            reg_data[j] = data_buf[j*2 + 1];
        }
        // data_buf.clear();
        // status = reg->dataReset(data.get());
        ASSERT_STATUS("Cannot get value from data");
        
        // printf("data buf size %d\n", (int)data_buf.size());
        // for (int i = 0; i < (int)data_buf.size(); i ++) {
        //     printf("%lx ", data_buf[i]);
        // }
        // printf("\n");

        if (table_id == 1 && logger.log_level >= Logger::Level::DEBUG) {
            int n_pkt = 0;
            int n_flow = 0;
            for (int i = 0; i < reg_size; i ++) {
                n_pkt += reg_data[i];
                n_flow += reg_data[i] > 0;
            }
            logger.debug("n_pkt ", n_pkt, ", n_flow ", n_flow);
        }
        return 0;
    }

    void start() override {
        init_check_app_table();
        init_fwd_table();
        init_fwd_to_sw_table();
        init_reg_size();

        builder.AddListeningPort(drv_server_addr, grpc::InsecureServerCredentials());
        builder.RegisterService(&drv_service);
        drv_server = builder.BuildAndStart();
        logger.info("Driver server listening on ", drv_server_addr);
        
        drv_server->Wait();
        return ;
    }

    int push_mb_policy(int _n_tenant, mb_policy_t* _plcs) override {
        n_tenant = _n_tenant;
        plcs = _plcs;
        char table_name[100];
        for (int i = 1; i <= 3; i ++) {
            sprintf(table_name, "SwitchIngress.getindex_%d.tenant_info", i);
            clear_table(table_name);
            sprintf(table_name, "SwitchIngress.getindex_%d.block_selector", i);
            clear_table(table_name);
            sprintf(table_name, "SwitchIngress.getindex_%d.block_selector_ap", i);
            clear_table(table_name);
            
            add_tenant_info_table(i, n_tenant, plcs);
        }
        return 0;
    }

    int register_shape(int* shapex_p, int* shapey_p) override {
        *shapex_p = 3;
        *shapey_p = reg_size;
        return 0;
    }

    int pull_record(int32_t* arr) override {
        double point1 = gettime_ms();
        for (int i = 0; i < 3; i ++) {
            record_register(i + 1, arr + i * reg_size);
        }
        double point2 = gettime_ms();
        for (int i = 0; i < 3; i ++) {
            clear_register(i + 1);
        }
        double point3 = gettime_ms();
        logger.perf("record time : ", point2 - point1, "ms, clear time : ", point3 - point2, "ms");
        sess->sessionCompleteOperations();
        return 0;
    }

    int sync_begin() override {
        clear_table("SwitchIngress.get_tid", true);
        return 0;
    }

    int sync_end() override {
        add_get_tid_table(n_tenant, plcs);
        delete_mb_policies(n_tenant, plcs);
        return 0;
    }


private:
    string drv_server_addr;
    DrvServiceImpl drv_service;
    unique_ptr<Server> drv_server;
    ServerBuilder builder;
    Logger &logger;

    int n_tenant;
    int reg_size;
    mb_policy_t* plcs;
};
