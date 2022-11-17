#pragma once
#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <grpcpp/security/server_credentials.h>

#include "drv_service.grpc.pb.h"

#include "mb_policy.hpp"
#include "vtest.hpp"
#include "global_config.hpp"

using grpc::Server;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::ServerWriter;
using grpc::Status;
using grpc::StatusCode;
using std::chrono::system_clock;
using namespace switchd;
using namespace std;

class DrvServiceImpl final : public DrvService::Service  {
public:
    explicit DrvServiceImpl(GlobalConfig &global_cfg,
                            VTest *_test)
                            : test(_test),
                              logger(global_cfg.logger) {
    }

    Status PushPullMB(ServerContext* context, const PushMBRequest* req,
                    PullResponse* res) {

        // Pull Record
        int shapex;
        int shapey;
        test->register_shape(&shapex, &shapey);
        // res->set_shapex(shapex);
        // res->set_shapey(shapey);
        res->mutable_arr()->Reserve(shapex * shapey);
        int32_t* arr = res->mutable_arr()->AddNAlreadyReserved(shapex * shapey);
        double pull_start = gettime_ms();
        test->pull_record(arr);
        double pull_end = gettime_ms();
        logger.perf("Pull time : ", pull_end - pull_start, "ms");
        double push_start = gettime_ms();

        // usleep(1000000);
        // Push Policy
        int n_tenant = req->p_size();

        mb_policy_t* plcs = (mb_policy_t*)malloc(n_tenant * sizeof(mb_policy_t));
        
        for (int t = 0; t < n_tenant; t ++) {
            const TenantMBPolicy& policy_p = req->p(t);
            plcs[t].token = policy_p.token();
            int n_vlan_id = policy_p.vlan_id_size();
            plcs[t].n_vlan_id = n_vlan_id;
            plcs[t].vlan_id = (uint16_t*)malloc(n_vlan_id * sizeof(uint16_t));
            for (int i = 0; i < n_vlan_id; i ++) {
                plcs[t].vlan_id[i] = (uint16_t)policy_p.vlan_id(i);
            }
            // if (logger.log_level >= Logger::DEBUG) {
            //     logger << "VlanId[" << t << "] : ";
            //     for (int i = 0; i < n_vlan_id; i ++) {
            //         logger << plcs[t].vlan_id[i] << ", ";
            //     }
            //     logger << "\n";
            // }
            int n_off = policy_p.off_size();
            plcs[t].n_off = n_off;
            plcs[t].off = (uint32_t*)malloc(n_off * sizeof(uint32_t));
            for (int i = 0; i < n_off; i ++) {
                plcs[t].off[i] = policy_p.off(i);
            }
            plcs[t].msk = policy_p.msk();
        }
        test->push_mb_policy(n_tenant, plcs);
        double push_end = gettime_ms();
        logger.perf("Push time : ", push_end - push_start, "ms");

        return Status::OK;
    }

    Status SyncBegin(ServerContext* context, const SyncBeginRequest* req,
                     SyncBeginResponse* res) {
        sync_start = gettime_ms();
        test->sync_begin();
        return Status::OK;
    }

    Status SyncEnd(ServerContext* context, const SyncEndRequest* req,
                   SyncEndResponse* res) {
        test->sync_end();
        double sync_end = gettime_ms();
        logger.perf("Total sync time : ", sync_end - sync_start, "ms");
        return Status::OK;
    }

    Status GetConfig(ServerContext* context, const GetConfigRequest* req,
                     GetConfigResponse* res) {
        uint16_t machineid = req->machine_id();
        int shapex;
        int shapey;
        test->machineid = machineid;
        test->register_shape(&shapex, &shapey);
        res->set_counter_depth(shapex);
        res->set_counter_size(shapey);

        return Status::OK;
    }

private:
    
    VTest* test;
    int n_tenant;
    Logger &logger;
    double sync_start;
};
