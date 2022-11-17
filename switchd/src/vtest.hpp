#pragma once

#include <cstdio>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <utility>

#include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_session.hpp>
#include <bf_rt/bf_rt_info.hpp>
#include <bf_rt/bf_rt_init.hpp>
#include <bf_rt/bf_rt_table.hpp>
#include <bf_rt/bf_rt_table_key.hpp>
#include <bf_rt/bf_rt_table_data.hpp>

extern "C" {
    #include <bf_switchd/bf_switchd.h>
    #include <tofino/bf_pal/bf_pal_types.h>
    #include <tofino/bf_pal/bf_pal_port_intf.h>
    #include <traffic_mgr/traffic_mgr_port_intf.h>
    #include <bfsys/bf_sal/bf_sys_log.h>
}

/*
#include "mb_policy.hpp"
#include "utils.hpp"
#include "global_config.hpp"
*/

using namespace std;

#define THRIFT_PORT_NUM 7777

#define CLEAR_BATCH_SIZE 2

#define ASSERT_STATUS(msg) if (status != BF_SUCCESS) { printf("ERROR:%s : %s\n", msg, bf_err_str(status)); return status; }

#define FUNC_NOT_IMPLEMENTED printf("Not Implemented!\n"); return -1;

// static uint32_t fp_ports[][2] = {{9, 0}, {10, 0}, {11, 0}, {12, 0}, {13, 0}, {14, 0}, {15, 0}, {16, 0}, {17, 0}, {18, 0}, {19, 0}};
static uint32_t fp_ports[][2] = {{7, 0}, {5, 0}, {3, 0}, {1, 0}};

class VTest {
public:
    uint16_t machineid;
    string p4_name;
    bf_rt_target_t dev_tgt;
    shared_ptr<bfrt::BfRtSession> sess;
    const bfrt::BfRtInfo *bfrtInfo;

    VTest(GlobalConfig &global_cfg) {
        p4_name = global_cfg.p4_name;
    }
    
    ~VTest() {
        bf_status_t status;
        
        status = sess->sessionDestroy();
    }

    /* init bf_switchd */
    void init_switchd() {

        unique_ptr<bf_switchd_context_t> switchd_main_ctx = make_unique<bf_switchd_context_t>();
        switchd_main_ctx->install_dir = getenv("SDE_INSTALL");
        char conf_file[100];
        sprintf(conf_file, "%s/share/p4/targets/tofino/%s.conf", switchd_main_ctx->install_dir, p4_name.c_str());

        switchd_main_ctx->conf_file = conf_file;
        switchd_main_ctx->skip_p4 = false;
        switchd_main_ctx->skip_port_add = false;
        switchd_main_ctx->running_in_background = true;
        switchd_main_ctx->dev_sts_port = THRIFT_PORT_NUM;
        switchd_main_ctx->dev_sts_thread = true;

        bf_switchd_lib_init(switchd_main_ctx.get());
    }

    /* init session, dev_target, bfrt_info */
    int init_program() {
        bf_status_t status;

        sess = bfrt::BfRtSession::sessionCreate();
        if (sess == nullptr) {
            cout << "Cannot create bfrt session" << endl;
            return 1;
        }

        dev_tgt.dev_id = 0;
        dev_tgt.pipe_id = 0xffff;

        auto &devMgr = bfrt::BfRtDevMgr::getInstance();

        /*vector<std::reference_wrapper<const std::string>> p4_names;
        status = devMgr.bfRtInfoP4NamesGet(dev_tgt.dev_id,
                                        p4_names);
        if (status != BF_SUCCESS) {
            printf("ERROR:Cannot get p4 names : %s\n", bf_err_str(status));
            return status;
        }
        
        cout << "List all p4 names :" << endl;
        for (auto p4_name : p4_names) {
            cout << "\n" << p4_name.get() << endl;
        }*/

        status = devMgr.bfRtInfoGet(dev_tgt.dev_id,
                                    p4_name,
                                    &bfrtInfo);
        if (status != BF_SUCCESS) {
            printf("ERROR: Cannot get BfRt info : %s\n", bf_err_str(status));
            return status;
        }
        return 0;
    }

    /* add and enable all ports */
    int init_port() {
        bf_status_t status;
        bf_pal_front_port_handle_t fp_hdl;
        int dev_port;

        for (uint32_t i = 0; i < sizeof(fp_ports) / sizeof(fp_ports[0]); i ++) {
            fp_hdl.conn_id = fp_ports[i][0];
            fp_hdl.chnl_id = fp_ports[i][1];
            status = bf_pal_front_port_to_dev_port_get(
                        dev_tgt.dev_id,
                        &fp_hdl,
                        &dev_port);
            ASSERT_STATUS("Cannot get dev port");
            status = bf_pal_port_add(
                        dev_tgt.dev_id,
                        dev_port,
                        BF_SPEED_100G,
                        BF_FEC_TYP_NONE);
            ASSERT_STATUS("Cannot add port");
            status = bf_pal_port_autoneg_policy_set(
                        dev_tgt.dev_id,
                        dev_port,
                        PM_AN_FORCE_DISABLE);
            ASSERT_STATUS("Cannot set autoneg_policy");
            status = bf_pal_port_enable(
                        dev_tgt.dev_id,
                        dev_port);
            ASSERT_STATUS("Cannot enable port");
        }

        // set cpu port
        // status = bf_tm_port_cpuport_set(dev_tgt.dev_id, 64);

        cout << "Successfully enabled all ports." << endl;
        return 0;
    }

    int print_tables() {
        bf_status_t status;
        
        vector<const bfrt::BfRtTable *> tables;
        status = bfrtInfo->bfrtInfoGetTables(&tables);
        ASSERT_STATUS("Cannot get BfRt tables");

        string table_name;
        bfrt::BfRtTable::TableType table_type;
        for (auto table : tables) {
            status = table->tableNameGet(&table_name);
            cout << "Find table : " << table_name << endl;
            status = table->tableTypeGet(&table_type);
            cout << "\ttype : " << int(table_type) << endl;
        }
        return 0;
    }

    int print_table_info(const bfrt::BfRtTable *table) {
        bf_status_t status;
        string tbl_name;
        bfrt::BfRtTable::TableType tbl_typ;

        status = table->tableNameGet(&tbl_name);
        status = table->tableTypeGet(&tbl_typ);
        cout << "Printing info of Table " << tbl_name << ", type : " << int(tbl_typ) << endl;
        vector<bf_rt_id_t> field_ids;

        /* print the key fields */
        status = table->keyFieldIdListGet(&field_ids);
        cout << "Key fields : " << endl;
        cout << "id\tname\t\t\ttype\tsize\tdata_typ" << endl;
        for (auto field_id : field_ids) {
            bfrt::KeyFieldType field_typ;
            bfrt::DataType field_data_typ;
            string field_name;
            size_t field_siz;
            status = table->keyFieldTypeGet(field_id, &field_typ);
            status = table->keyFieldDataTypeGet(field_id, &field_data_typ);
            status = table->keyFieldNameGet(field_id, &field_name);
            status = table->keyFieldSizeGet(field_id, &field_siz);
            cout << field_id << "\t" << field_name << "\t" << int(field_typ) << "\t" << field_siz << "\t" << int(field_data_typ) << endl;
        }
        field_ids.clear();

        /* print the data fields */
        if (tbl_typ == bfrt::BfRtTable::TableType::MATCH_DIRECT || 
            tbl_typ == bfrt::BfRtTable::TableType::ACTION_PROFILE) {
            // print the data fields for match-action tables
            vector<bf_rt_id_t> action_ids;
            string action_name;

            status = table->actionIdListGet(&action_ids);
            for (auto action_id : action_ids) {
                status = table->actionNameGet(action_id, &action_name);
                status = table->dataFieldIdListGet(action_id, &field_ids);

                cout << "Action " << action_id << " " << action_name << endl;
                cout << "\tAction's data fields : " << endl;
                cout << "\tid\tname\tsize\tdata_typ" << endl;
                for (auto field_id : field_ids) {
                    bfrt::DataType field_data_typ;
                    string field_name;
                    size_t field_siz;
                    status = table->dataFieldDataTypeGet(field_id, action_id, &field_data_typ);
                    status = table->dataFieldNameGet(field_id, action_id, &field_name);
                    status = table->dataFieldSizeGet(field_id, action_id, &field_siz);
                    
                    cout << "\t" << field_id << "\t" << field_name << "\t" << field_siz << "\t" << int(field_data_typ) << endl;
                }
                field_ids.clear();
            }
        }
        else {
            // print the data fields for key-value tables
            status = table->dataFieldIdListGet(&field_ids);
            cout << "Data fields : " << endl;
            cout << "id\tname\t\t\tsize\tdata_typ" << endl;
            for (auto field_id : field_ids) {
                bfrt::DataType field_data_typ;
                string field_name;
                size_t field_siz;
                status = table->dataFieldDataTypeGet(field_id, &field_data_typ);
                status = table->dataFieldNameGet(field_id, &field_name);
                status = table->dataFieldSizeGet(field_id, &field_siz);
                
                cout << field_id << "\t" << field_name << "\t" << field_siz << "\t" << int(field_data_typ) << endl;
            }
            field_ids.clear();
        }
        cout << "Print table info complete." << endl;
        return 0;
    }

    int clear_table(const bfrt::BfRtTable *table, bool is_atomic=false) {
        bf_status_t status;
        const bfrt::BfRtTable::BfRtTableGetFlag flag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW;

        if (is_atomic) {
            status = sess->beginTransaction(is_atomic);
        }
        int n_entry = 0;
        const int n_get = 100;
        vector<unique_ptr<bfrt::BfRtTableKey> > ukeys;
        vector<unique_ptr<bfrt::BfRtTableData> > udatas;
        // get first entry
        ukeys.emplace_back();
        udatas.emplace_back();
        status = table->keyAllocate(&(ukeys.back()));
        status = table->dataAllocate(&(udatas.back()));
        
        status = table->tableEntryGetFirst(*sess, dev_tgt, flag, ukeys.back().get(), udatas.back().get());
        if (status == BF_SUCCESS) {
            n_entry = 1;
            while (1) {
                vector<pair<bfrt::BfRtTableKey *, bfrt::BfRtTableData *> > kds;
                bfrt::BfRtTableKey *last_key = ukeys.back().get();
                int n_got;
                for (int i = 0; i < n_get; i ++) {
                    ukeys.emplace_back();
                    udatas.emplace_back();
                    status = table->keyAllocate(&(ukeys.back()));
                    status = table->dataAllocate(&(udatas.back()));

                    kds.push_back(make_pair(ukeys.back().get(), udatas.back().get()));
                }
                status = table->tableEntryGetNext_n(
                    *sess, dev_tgt, *last_key, n_get, flag, &kds, (uint32_t *)&n_got
                );
                ASSERT_STATUS("tableEntryGetNext_n failed");
                n_entry += n_got;
                if (n_got < n_get)
                    break;
            }
        }

        for (int i = 0; i < n_entry; i ++) {
            bfrt::BfRtTableKey *key = ukeys[i].get();
            status = table->tableEntryDel(*sess, dev_tgt, *key);
            ASSERT_STATUS("tableEntryDel failed");
        }
        if (is_atomic) {
            status = sess->verifyTransaction();
            ASSERT_STATUS("verifyTransaction failed");
            status = sess->commitTransaction(true);
            ASSERT_STATUS("commitTransaction failed");
        }
        else {
            status = sess->sessionCompleteOperations();
            ASSERT_STATUS("sessionCompleteOperations failed");
        }

        
        ukeys.emplace_back();
        udatas.emplace_back();
        status = table->keyAllocate(&(ukeys.back()));
        status = table->dataAllocate(&(udatas.back()));
        status = table->tableEntryGetFirst(*sess, dev_tgt, flag, ukeys.back().get(), udatas.back().get());
        if (status == 0) {
            printf("ERROR! table not cleared!\n");
        }
        return 0;
    }

    int clear_table(const string &table_name, bool is_atomic=false) {
        bf_status_t status;
        const bfrt::BfRtTable *table = nullptr;
        status = bfrtInfo->bfrtTableFromNameGet(table_name, &table);
        return clear_table(table, is_atomic);
    }

    
    /*int dump_table(const bfrt::BfRtTable *table) {
        bf_status_t status;
        bfrt::BfRtTable::BfRtTableGetFlag flag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW;
        bfrt::BfRtTable::TableType tbl_typ;
        string tbl_name;

        status = table->tableNameGet(&tbl_name);
        status = table->tableTypeGet(&tbl_typ);
        cout << "Dump table " << tbl_name << " with type " << (int)tbl_typ << endl;
        if (tbl_typ == bfrt::BfRtTable::TableType::MATCH_DIRECT || 
            tbl_typ == bfrt::BfRtTable::TableType::ACTION_PROFILE) {

            vector<bf_rt_id_t> action_ids;

            status = table->actionIdListGet(&action_ids);
            for (auto action_id : action_ids) {
                string action_name;
                status = table->actionNameGet(action_id, &action_name);
                cout << " Entries of Action " << action_name << " : " << endl;

                vector<pair<unique_ptr<bfrt::BfRtTableKey>, unique_ptr<bfrt::BfRtTableData> > > upairs;
                bfrt::BfRtTable::keyDataPairs pairs;
                uint32_t n_entry = 0;
                upairs.push_back(make_pair(unique_ptr<bfrt::BfRtTableKey>(), unique_ptr<bfrt::BfRtTableData>()));
                status = table->keyAllocate(&upairs[0].first);
                status = table->dataAllocate(action_id, &upairs[0].second);

                status = table->tableEntryGetFirst(*sess, dev_tgt, flag, upairs[0].first.get(), upairs[0].second.get());
                if (status != BF_SUCCESS)
                    continue;
                while (1) {
                    uint32_t lastp = upairs.size() - 1;
                    uint32_t ret;
                    for (uint32_t i = 0; i < CLEAR_BATCH_SIZE; i ++) {
                        upairs.push_back(make_pair(unique_ptr<bfrt::BfRtTableKey>(), unique_ptr<bfrt::BfRtTableData>()));
                        uint32_t curp = upairs.size() - 1;
                        status = table->keyAllocate(&upairs[curp].first);
                        status = table->dataAllocate(action_id, &upairs[curp].second);
                        pairs.push_back(make_pair(upairs[curp].first.get(), upairs[curp].second.get()));
                    }
                    status = table->tableEntryGetNext_n(*sess, dev_tgt, *upairs[lastp].first, CLEAR_BATCH_SIZE, flag, &pairs, &ret);

                    pairs.clear();
                    n_entry += ret;
                    if (ret < CLEAR_BATCH_SIZE)
                        break;
                }
                for (uint32_t i = 0; i < n_entry; i ++) {
                    table->tableEntryDel(*sess, dev_tgt, *upairs[i].first);
                }
                upairs.clear();
                
                unique_ptr<bfrt::BfRtTableKey> key;
                unique_ptr<bfrt::BfRtTableData> data;
                status = table->keyAllocate(&key);
                status = table->dataAllocate(action_id, &data);
                while (1) {
                    status = table->tableEntryGetFirst(*sess, dev_tgt, flag, key.get(), data.get());
                    if (status != BF_SUCCESS)
                        break;
                    status = table->tableEntryDel(*sess, dev_tgt, *key);
                    ASSERT_STATUS("Cannot delete entry");
                }
            }
        }
        else {
            
            unique_ptr<bfrt::BfRtTableKey> key;
            unique_ptr<bfrt::BfRtTableData> data;
            status = table->keyAllocate(&key);
            status = table->dataAllocate(&data);
            while (1) {
                status = table->tableEntryGetFirst(*sess, dev_tgt, flag, key.get(), data.get());
                if (status != BF_SUCCESS)
                    break;
                status = table->tableEntryDel(*sess, dev_tgt, *key);
                ASSERT_STATUS("Cannot delete entry");
            }
        }
        
        sess->sessionCompleteOperations();
        return 0;
    }*/

    void initialize() {
        init_switchd();
        init_program();
        init_port();
        // print_tables();
    }

    virtual void start() = 0;

    virtual int push_mb_policy(int n_tenant, mb_policy_t* plcs) {FUNC_NOT_IMPLEMENTED}

    virtual int register_shape(int* shapex_p, int* shapey_p) {FUNC_NOT_IMPLEMENTED}

    virtual int pull_record(int32_t* arr) {FUNC_NOT_IMPLEMENTED}

    virtual int sync_begin() {FUNC_NOT_IMPLEMENTED}

    virtual int sync_end() {FUNC_NOT_IMPLEMENTED}
};
