#ifndef BPF_ATTACH_MANAGER_H
#define BPF_ATTACH_MANAGER_H

#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <condition_variable>

#include "bpf_tool/bpf_types.hpp"
#include "bpf_tool/bpf_attacher.h"
#include "nic_check/interface_loader.h"

namespace bpf_tool{
    class BpfAttachManager{
    public:
        using AttacherPtr = std::shared_ptr<Attacher>;
        static BpfAttachManager& get_instance(){
            static BpfAttachManager manager;
            return manager;
        }

        AttacherPtr create_attacher(BpfProgramPtr prog, AttachSpec spec){
            std::lock_guard<std::mutex> lock(attacher_mutex_);
            auto attacher = std::make_shared<Attacher>(prog, spec, attachers_.size(), [this](int id){attacher_policy_change_process(id);});
            attachers_.push_back(attacher);
            return attacher;
        }

    private:
        std::mutex attacher_mutex_;
        std::vector<AttacherPtr> attachers_;
        std::jthread retry_thread_;
        nic_check::InterfaceLoader loader_;
        std::condition_variable retry_cv_;
        std::mutex retry_cv_mutex_;
        std::unordered_set<int> failed_apply_attacher_ids_;

        BpfAttachManager();
        ~BpfAttachManager();
        void attacher_policy_change_process(int id);

        void append_failed_attacher_id(int id);
        bool apply_targets_policy_per_attacher(int id);
        bool is_attach_filter(const std::string& nic_name, BpfProgramPtr prog, AttachSpec spec);
        bool attach_filter(const std::string& nic_name, BpfProgramPtr prog, AttachSpec spec);
        bool detach_filter(const std::string& nic_name, BpfProgramPtr prog, AttachSpec spec);
    };
}

#endif