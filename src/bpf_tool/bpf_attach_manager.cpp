#include "bpf_tool/bpf_attach_manager.h"

#include <thread>
#include <chrono>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <unistd.h>

#include "utils/logger.hpp"
#include "nic_check/interface_loader.h"

using namespace std;
using namespace bpf_tool;
using namespace utils;
using namespace nic_check;
using namespace chrono_literals;

namespace {
    InterfaceLoader loader;
    atomic<bool> is_need_retry{false};
    jthread retry_thread;

    bool is_attach_filter(const string& nic_name, BpfProgramPtr prog, AttachSpec spec){
        int ifindex = loader.get_ifindex_by_ifname(nic_name);

        struct bpf_tc_hook hook = {};
        hook.sz           = sizeof(hook);
        hook.ifindex      = ifindex;
        hook.attach_point = spec.is_ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;

        struct bpf_tc_opts query = {};
        query.sz = sizeof(query);
        query.handle = spec.handle;
        query.priority = spec.priority;
        query.prog_id = prog->prog_id;

        int rc = bpf_tc_query(&hook, &query);
        if(rc == 0 && query.prog_id == prog_id_) return true;
        return false;
    }

    bool attach_filter(const string& nic_name, BpfProgramPtr prog, AttachSpec spec){
        if(is_applied_filter(nic_name, prog, spec)) 
            return true;

        int ifindex = loader.get_ifindex_by_ifname(nic_name);

        struct bpf_tc_hook hook = {};
        hook.sz           = sizeof(hook);
        hook.ifindex      = ifindex;
        hook.attach_point = spec.is_ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;

        int rc = bpf_tc_hook_create(&hook);
        if (rc && rc != -EEXIST)
            return false;

        struct bpf_tc_opts opts = {};
        opts.sz       = sizeof(opts);
        opts.prog_fd  = prog->fd;
        opts.handle   = spec.handle;
        opts.priority = spec.priority;
        opts.flags    = BPF_TC_F_REPLACE;
        rc = bpf_tc_attach(&hook, &opts);
        if(rc) return false;

        return true;
    }
}

BpfAttachManager::BpfAttachManager(){
    retry_thread = jthread([this](std::stop_token stop){
        while(!stop.stop_requested()){
            is_need_retry.wait(false);
            if(stop.stop_requested()) break;

            bool is_success = false;
            decltype(failed_requests_) pending_requests;
            {
                lock_guard<mutex> lock(failed_nics_mutex_);
                pending_requests.swap(failed_requests_);
            }

            for(const auto& request: pending_requests){
                if(request.gen < this->generation_.load()) continue;


            }
        }
    }
}
BpfAttachManager::~BpfAttachManager(){

}