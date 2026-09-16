#include "bpf_tool/bpf_attach_manager.h"

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

}

BpfAttachManager::BpfAttachManager(){
    retry_thread_ = jthread([this](std::stop_token stop){
        while(!stop.stop_requested()){
            unordered_set<int> failed_attacher_ids_snap;
            {
                unique_lock<mutex> lock(retry_cv_mutex_);
                retry_cv_.wait_for(lock, 1000ms, [this, &stop](){
                    return !failed_apply_attacher_ids_.empty() || stop.stop_requested();
                });
                if(stop.stop_requested()) break;

                failed_attacher_ids_snap.swap(failed_apply_attacher_ids_);
            }

            for(int id: failed_attacher_ids_snap){
                bool success = apply_targets_policy_per_attacher(id);
                if(!success){
                    utils::log("failed apply id: " + to_string(id));
                }
            }
        }
    });

    loader_.start_monitor([this](InterfaceLoader::SnapshotPtr snaps){
        (void)snaps;

        int count;
        {
            lock_guard<mutex> lock(attacher_mutex_);
            count = attachers_.size();
        }
        for(int i=0; i<count; i++)
            append_failed_attacher_id(i);
        
        retry_cv_.notify_all();
    });
}
BpfAttachManager::~BpfAttachManager(){
    if(retry_thread_.joinable()){
        retry_thread_.request_stop();
        retry_thread_.join();
        retry_cv_.notify_all();
    }

    loader_.stop_monitor();
}

void BpfAttachManager::attacher_policy_change_process(int id){
    append_failed_attacher_id(id);
    retry_cv_.notify_one();
}

void BpfAttachManager::append_failed_attacher_id(int id){
    lock_guard<mutex> lock(retry_cv_mutex_);
    failed_apply_attacher_ids_.insert(id);
}

bool BpfAttachManager::apply_targets_policy_per_attacher(int id){
    PolicyPtr policy_ptr;
    AttachSpec snap_attach_spec;
    BpfProgramPtr prog_ptr;
    {
        lock_guard<mutex> lock(attacher_mutex_);
        policy_ptr = attachers_[id]->get_targets();
        snap_attach_spec = attachers_[id]->get_attach_spec();
        prog_ptr = attachers_[id]->get_bpf_prog();
    }

    bool is_all = policy_ptr->is_all;
    auto interfaces = loader_.snapshot();
    bool is_apply_success = true;
    for(const auto& [nic_name, info]: *interfaces){
        if(policy_ptr->policy->contains(nic_name) || is_all){
            bool is_attach = attach_filter(nic_name, prog_ptr, snap_attach_spec);
            if(!is_attach) {
                utils::log("failed attach ifname: " + nic_name);
                is_apply_success = false;
            }
        }
        else{
            bool is_detach = detach_filter(nic_name, prog_ptr, snap_attach_spec);
            if(!is_detach) {
                utils::log("failed detach ifname: " + nic_name);
                is_apply_success = false;
            }
        }
    }

    if(!is_apply_success){
        append_failed_attacher_id(id);
        retry_cv_.notify_one();
    }
    return is_apply_success;
}

bool BpfAttachManager::is_attach_filter(const string& nic_name, BpfProgramPtr prog, AttachSpec spec){
    int ifindex = loader_.get_ifindex_by_ifname(nic_name);

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
    if(rc == 0 && query.prog_id == prog->prog_id) return true;
    return false;
}

bool BpfAttachManager::attach_filter(const string& nic_name, BpfProgramPtr prog, AttachSpec spec){
    int ifindex = loader_.get_ifindex_by_ifname(nic_name);

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

bool BpfAttachManager::detach_filter(const string& nic_name, BpfProgramPtr prog, AttachSpec spec){
    if(!is_attach_filter(nic_name, prog, spec)) return true;

    int ifindex = loader_.get_ifindex_by_ifname(nic_name);

    struct bpf_tc_hook hook = {};
    hook.sz           = sizeof(hook);
    hook.ifindex      = ifindex;
    hook.attach_point = spec.is_ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;

    struct bpf_tc_opts opts = {};
    opts.sz       = sizeof(opts);
    opts.handle   = spec.handle;
    opts.priority = spec.priority;
    // prog_fd / prog_id / flags 는 0 이어야 한다

    int rc = bpf_tc_detach(&hook, &opts);
    if(rc == 0 || rc == -ENOENT)     // 없으면 이미 목적 달성
        return true;

    return false;
}