#include "bpf_tool/bpf_attacher.h"

using namespace std;
using namespace bpf_tool;

Attacher::Attacher(BpfProgramPtr prog, const AttachSpec spec, int id, Attacher::PolicyChangeCallback callback)
    : prog_{prog}, attach_spec_{spec}, id_{id}, notify_change_policy_{move(callback)} {}

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
    if(mode_.load() == AttachMode::kAttachSelective && is_changed && notify_change_policy_)
        notify_change_policy_(id_);
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
    if(mode_.load() == AttachMode::kAttachSelective && is_changed && notify_change_policy_)
        notify_change_policy_(id_);
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
    if(mode_.load() == AttachMode::kAttachSelective && is_changed && notify_change_policy_)
        notify_change_policy_(id_);
}
Attacher::FilterTargets Attacher::get_targets(){
    Attacher::FilterTargets targets;
    {
        lock_guard<mutex> lock(nics_list_mutex_);
        for(const auto& t: target_nics_)
            targets.insert(t);
    }
    return targets;
}

void Attacher::set_mode(AttachMode mode){
    auto old = mode_.exchange(mode);

    if(notify_change_policy_ && old != mode)
        notify_change_policy_(id_);
}
AttachMode Attacher::get_mode(){
    return mode_.load();
}