#include "bpf_tool/bpf_attacher.h"

using namespace std;
using namespace bpf_tool;

Attacher::Attacher(BpfProgramPtr prog, const AttachSpec spec, int id, Attacher::PolicyChangeCallback callback)
    : id_{id}, prog_{prog}, attach_spec_{spec}, notify_change_policy_{move(callback)}, policy_snapshot_{make_shared<Policy>()} {}

Attacher::~Attacher(){}

void Attacher::add_target(const string& nic_name){
    bool is_changed = false;
    {
        lock_guard<mutex> lock(nics_list_mutex_);
        if(target_nics_.find(nic_name) == target_nics_.end()){
            target_nics_.insert(nic_name);
            is_changed = true;
        }
    }
    if(mode_.load() == AttachMode::kAttachSelective && is_changed)
        change_policy();
}
void Attacher::remove_target(const string& nic_name){
    bool is_changed = false;
    {
        lock_guard<mutex> lock(nics_list_mutex_);
        if(target_nics_.find(nic_name) != target_nics_.end()){
            target_nics_.erase(nic_name);
            is_changed = true;
        }
    }
    if(mode_.load() == AttachMode::kAttachSelective && is_changed)
        change_policy();
}
void Attacher::clear_targets(){
    bool is_changed = false;
    {
        lock_guard<mutex> lock(nics_list_mutex_);
        if(!target_nics_.empty()){
            target_nics_.clear();
            is_changed = true;
        }
    }
    if(mode_.load() == AttachMode::kAttachSelective && is_changed)
        change_policy();
}

PolicyPtr Attacher::get_targets(){
    lock_guard<mutex> lock(snapshot_mutex_);
    return policy_snapshot_;
}

void Attacher::set_mode(AttachMode mode){
    auto old = mode_.exchange(mode);
    if(old != mode)
        change_policy();
}

AttachMode Attacher::get_mode(){
    return mode_.load();
}

void Attacher::change_policy(){
    FilterTargets targets_snaps;
    {
        lock_guard<mutex> targets_lock(nics_list_mutex_);
        for(const auto& nic: target_nics_)
            targets_snaps.insert(nic);
    }
    {
        lock_guard<mutex> snaps_lock(snapshot_mutex_);
        policy_snapshot_->policy->swap(targets_snaps);
        policy_snapshot_->is_all = (mode_.load() == AttachMode::kAttachAll ? true : false);
    }
    
    if(notify_change_policy_)
        notify_change_policy_(id_);
}