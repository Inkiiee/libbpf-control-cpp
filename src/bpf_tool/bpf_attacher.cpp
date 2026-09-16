#include "bpf_tool/bpf_attacher.h"

using namespace std;
using namespace bpf_tool;

Attacher::Attacher(BpfProgramPtr prog, const AttachSpec spec, int id, Attacher::PolicyChangeCallback callback)
    : id_{id}, prog_{prog}, attach_spec_{spec}, notify_change_policy_{move(callback)}, policy_snapshot_{make_shared<PolicyType>()} {}

Attacher::~Attacher(){}

void Attacher::add_target(const string& nic_name){
    bool is_changed = false;
    {
        lock_guard<mutex> lock(nics_list_mutex_);
        bool policy_changed = false;
        if(target_nics_.find(nic_name) == target_nics_.end()){
            target_nics_.insert(nic_name);
            policy_changed = true;
        }
        if(mode_ == AttachMode::kAttachSelective && policy_changed)
            is_changed = true;
    }
    if(is_changed)
        change_policy();
}
void Attacher::remove_target(const string& nic_name){
    bool is_changed = false;
    {
        lock_guard<mutex> lock(nics_list_mutex_);
        bool policy_changed = false;
        if(target_nics_.find(nic_name) != target_nics_.end()){
            target_nics_.erase(nic_name);
            policy_changed = true;
        }
        if(mode_ == AttachMode::kAttachSelective && policy_changed)
            is_changed = true;
    }
    if(is_changed)
        change_policy();
}
void Attacher::clear_targets(){
    bool is_changed = false;
    {
        lock_guard<mutex> lock(nics_list_mutex_);
        bool policy_changed = false;
        if(!target_nics_.empty()){
            target_nics_.clear();
            policy_changed = true;
        }
        if(mode_ == AttachMode::kAttachSelective && policy_changed)
            is_changed = true;
    }
    if(is_changed)
        change_policy();
}

PolicyPtr Attacher::get_targets(){
    lock_guard<mutex> lock(nics_list_mutex_);
    return policy_snapshot_;
}

void Attacher::set_mode(AttachMode mode){
    AttachMode old;
    {
        lock_guard<mutex> lock(nics_list_mutex_);
        old = mode_;
        mode_ = mode;
    }
    if(old != mode)
        change_policy();
}

AttachMode Attacher::get_mode(){
    lock_guard<mutex> lock(nics_list_mutex_);
    return mode_;
}

void Attacher::change_policy(){
    PolicyType new_policy;
    {
        lock_guard<mutex> targets_lock(nics_list_mutex_);
        auto next = make_shared<const PolicyType>(
            target_nics_,
            (mode_ == AttachMode::kAttachAll ? true : false)
        );
        policy_snapshot_ = move(next);
    }
    
    if(notify_change_policy_)
        notify_change_policy_(id_);
}