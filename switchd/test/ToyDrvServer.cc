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
#include "global_config.hpp"

extern "C" {

}

using grpc::Server;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::ServerWriter;
using grpc::ServerBuilder;
using grpc::Status;
using grpc::StatusCode;
using std::chrono::system_clock;
using namespace std;
using namespace switchd;

class ToyDrvServiceImpl final : public DrvService::Service {
public:

    int counter_size;
    int counter_depth;

    explicit ToyDrvServiceImpl(GlobalConfig &global_cfg)
        : logger(global_cfg.logger) {
        counter_size = 10000;
        counter_depth = 3;
    }

    Status GetConfig(ServerContext* context, const GetConfigRequest* req,
                     GetConfigResponse* res) override {
        logger << "GetConfig" << "\n";
        logger << "\tMid : " << req->machine_id() << "\n";
        res->set_counter_size(counter_size);
        res->set_counter_depth(counter_depth);
        return Status::OK;
    }
    
    Status PushPullMB(ServerContext* context, const PushMBRequest* req,
                    PullResponse* res) override {
        
        logger << "ToyDrvServer<<<PushPull" << "\n";
        int n_tenant = req->p_size();
        for (int t = 0; t < n_tenant; t ++) {
            const TenantMBPolicy& policy = req->p(t);
            
            logger << "\tToken : " << policy.token() << "\n";
            int vlan_id_size = policy.vlan_id_size();
            logger << "\tVlanId : ";
            for (int i = 0; i < vlan_id_size; i ++) {
                logger << policy.vlan_id(i) << " ";
            }
            logger << "\n";
            int off_size = policy.off_size();
            logger << "\tOff : ";
            for (int i = 0; i < off_size; i ++) {
                logger << policy.off(i) << " ";
            }
            logger << "\n";
            logger << "\tMsk : " << policy.msk() << "\n";
        }

        res->mutable_arr()->Reserve(counter_depth * counter_size);
        int32_t* arr = res->mutable_arr()->AddNAlreadyReserved(counter_depth * counter_size);
        for (int i = 0; i < counter_depth * counter_size; i ++) {
            arr[i] = i / counter_size + 1;
        }
        
        return Status::OK;
    }

    Status SyncBegin(ServerContext* context, const SyncBeginRequest* req,
                   SyncBeginResponse* res) {
        return Status::OK;
    }

    Status SyncEnd(ServerContext* context, const SyncEndRequest* req,
                   SyncEndResponse* res) {
        return Status::OK;
    }

private:
    Logger &logger;
};


class ToyDrvServer {
public:
    string drv_server_addr;
    ToyDrvServiceImpl drv_service;
    unique_ptr<Server> drv_server;
    ServerBuilder builder;
    Logger &logger;

    ToyDrvServer(GlobalConfig &global_cfg)
        : drv_server_addr(global_cfg.drv_service_addr),
          drv_service(global_cfg),
          logger(global_cfg.logger) {
        logger << "ToyDrvServer listening on " << drv_server_addr << "\n";
    }

    void start() {
        builder.AddListeningPort(drv_server_addr, grpc::InsecureServerCredentials());
        builder.RegisterService(&drv_service);
        drv_server = builder.BuildAndStart();
        
        drv_server->Wait();
    }
};


int
main(int argc, char **argv)
{
    GlobalConfig global_cfg;
    global_cfg.parse(argc, argv);

    /* start Drv server */
    ToyDrvServer drv_server(global_cfg);
    drv_server.start();
    
    return 0;
}
