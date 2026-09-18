#include "bpf_tool/bpf_attach_manager.h"

#include <algorithm>
#include <cerrno>
#include <system_error>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include "nic_check/interface_loader.h"
#include "utils/logger.hpp"
#include "bpf_runtime/bpf_runtime.hpp"

using namespace std;
using namespace bpf_tool;
using namespace utils;
using namespace nic_check;
using namespace chrono_literals;

namespace {
    inline constexpr auto kDefaultDelay = 500ms;
    inline constexpr int kMaxRetryCount = 5;
}

BpfAttachManager::BpfAttachManager(){
    if(bpf_runtime::initialize() < 0){
        utils::log("bpf runtime initialize failed");
        is_valid_ = false;
        return;
    }

    is_valid_ = true;
    retry_thread_ = jthread([this](std::stop_token stop){
        while(!stop.stop_requested()){
            ApplyRequestQueue ready;
            {
                unique_lock<mutex> lock(retry_cv_mutex_);
                retry_cv_.wait(lock, [this, &stop]{
                    return stop.stop_requested() || !apply_requests_.empty();
                });

                while(!stop.stop_requested() && ready.empty()){
                    const auto now = Clock::now();
                    for(auto it = apply_requests_.begin(); it != apply_requests_.end(); ){
                        const auto due = it->request_time + it->retry_count * kDefaultDelay;
                        if(it->is_immediate || due <= now){
                            ready.insert(*it);
                            it = apply_requests_.erase(it);
                        } else {
                            ++it;
                        }
                    }

                    if(!ready.empty())
                        break;

                    auto wake_at = TimePoint::max();
                    for(const auto& request: apply_requests_){
                        const auto due = request.request_time + request.retry_count * kDefaultDelay;
                        wake_at = std::min(wake_at, due);
                    }

                    // 새 요청이 들어오면 즉시 깨어나 마감 시간을 다시 계산한다.
                    retry_cv_.wait_until(lock, wake_at);
                }
            }

            if(stop.stop_requested())
                break;

            for(const auto& request: ready){
                if(!apply_targets_policy_per_attacher(request))
                    utils::log("failed apply id: " + to_string(request.id));
            }
        }
    });

    bool success = loader_.start_monitor([this](InterfaceLoader::SnapshotPtr snaps){
        (void)snaps;

        int count;
        {
            lock_guard<mutex> lock(attacher_mutex_);
            count = attachers_.size();
        }
        for(int i=0; i<count; i++)
            append_apply_request(ApplyRequest(i, true));
    });
    if(!success){
        is_valid_ = false;
        if(retry_thread_.joinable()){
            retry_thread_.request_stop();
            retry_cv_.notify_all();
            retry_thread_.join();
        }
    }
}
BpfAttachManager::~BpfAttachManager(){
    if(!is_valid_) return;

    loader_.stop_monitor();
    if(retry_thread_.joinable()){
        retry_thread_.request_stop();
        retry_cv_.notify_all();
        retry_thread_.join();
    }
}

void BpfAttachManager::attacher_policy_change_process(int id){
    append_apply_request(ApplyRequest(id, true));
}

void BpfAttachManager::append_apply_request(ApplyRequest request){
    bool changed = false;
    {
        lock_guard<mutex> lock(retry_cv_mutex_);
        auto it = apply_requests_.find(request);
        if(it == apply_requests_.end()){
            apply_requests_.insert(request);
            changed = true;
        } else if(it->request_time <= request.request_time){
            apply_requests_.erase(it);
            apply_requests_.insert(request);
            changed = true;
        }
    }

    if(changed)
        retry_cv_.notify_one();
}

bool BpfAttachManager::apply_targets_policy_per_attacher(ApplyRequest request){
    PolicyPtr policy_ptr;
    AttachSpec snap_attach_spec;
    BpfProgramPtr prog_ptr;
    {
        lock_guard<mutex> lock(attacher_mutex_);
        policy_ptr = attachers_[request.id]->get_targets();
        snap_attach_spec = attachers_[request.id]->get_attach_spec();
        prog_ptr = attachers_[request.id]->get_bpf_prog();
    }

    bool is_all = policy_ptr->is_all;
    auto interfaces = loader_.snapshot();
    bool is_apply_success = true;
    for(const auto& [nic_name, info]: *interfaces){
        (void)info;
        if(policy_ptr->policy.contains(nic_name) || is_all){
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
        request.is_immediate = false;
        if(++request.retry_count > kMaxRetryCount){
            utils::log(
                "Attacher index " + std::to_string(request.id) +
                " exceeded the maximum retry count."
            );
            return false;
        }
        append_apply_request(request);
    }
    return is_apply_success;
}

BpfAttachManager::FilterQueryResult BpfAttachManager::query_filter(
    const string& nic_name, BpfProgramPtr prog, AttachSpec spec)
{
    int ifindex = loader_.get_ifindex_by_ifname(nic_name);
    if(ifindex <= 0)
        return {FilterState::kError, -ENODEV};

    struct bpf_tc_hook hook = {};
    hook.sz           = sizeof(hook);
    hook.ifindex      = ifindex;
    hook.attach_point = spec.is_ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;

    struct bpf_tc_opts query = {};
    query.sz       = sizeof(query);
    query.handle   = spec.handle;
    query.priority = spec.priority;

    int rc = bpf_tc_query(&hook, &query);
    if(rc == -ENOENT)
        return {FilterState::kNotFound, 0};
    if(rc != 0)
        return {FilterState::kError, rc};
    if(query.prog_id == prog->prog_id)
        return {FilterState::kOurProgram, 0};
    return {FilterState::kOtherProgram, 0};
}

bool BpfAttachManager::attach_filter(const string& nic_name, BpfProgramPtr prog, AttachSpec spec){
    const auto query = query_filter(nic_name, prog, spec);
    if(query.state == FilterState::kOurProgram)
        return true;
    if(query.state == FilterState::kError){
        error_code ec(-query.error, std::generic_category());
        utils::log("bpf_tc_query failed while attaching " + nic_name + ": " + ec.message());
        return false;
    }

    int ifindex = loader_.get_ifindex_by_ifname(nic_name);
    if(ifindex <= 0)
        return false;

    struct bpf_tc_hook hook = {};
    hook.sz           = sizeof(hook);
    hook.ifindex      = ifindex;
    hook.attach_point = spec.is_ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;

    int rc = bpf_tc_hook_create(&hook);
    if(rc && rc != -EEXIST)
        return false;

    struct bpf_tc_opts opts = {};
    opts.sz       = sizeof(opts);
    opts.prog_fd  = prog->fd;
    opts.handle   = spec.handle;
    opts.priority = spec.priority;
    opts.flags    = query.state == FilterState::kOtherProgram ? BPF_TC_F_REPLACE : 0;

    rc = bpf_tc_attach(&hook, &opts);
    return rc == 0;
}

bool BpfAttachManager::detach_filter(const string& nic_name, BpfProgramPtr prog, AttachSpec spec){
    const auto query = query_filter(nic_name, prog, spec);
    if(query.state == FilterState::kError){
        error_code ec(-query.error, std::generic_category());
        utils::log("bpf_tc_query failed while detaching " + nic_name + ": " + ec.message());
        return false;
    }
    if(query.state != FilterState::kOurProgram)
        return true;

    int ifindex = loader_.get_ifindex_by_ifname(nic_name);
    if(ifindex <= 0)
        return false;

    struct bpf_tc_hook hook = {};
    hook.sz           = sizeof(hook);
    hook.ifindex      = ifindex;
    hook.attach_point = spec.is_ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;

    struct bpf_tc_opts opts = {};
    opts.sz       = sizeof(opts);
    opts.handle   = spec.handle;
    opts.priority = spec.priority;

    int rc = bpf_tc_detach(&hook, &opts);
    return rc == 0 || rc == -ENOENT;
}
