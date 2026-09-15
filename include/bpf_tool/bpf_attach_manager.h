#ifndef BPF_ATTACH_MANAGER_H
#define BPF_ATTACH_MANAGER_H

#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>

#include "bpf_tool/bpf_types.hpp"
#include "bpf_tool/bpf_attacher.h"

namespace bpf_tool{
    struct AttachRequest{
        std::string nic_name;
        AttachSpec spec;
        std::uint64_t gen;
        int retry_count{0};

        BpfAttachOp op{BpfAttachOp::kAttach};

        std::shared_ptr<BpfProgram> program_handle;
    };

    enum class BpfAttachRequestError{
        kNoError = 0,
        kQueueFullError = 1,
    };

    class BpfAttachManager{
    public:
        using AttacherPtr = std::shared_ptr<Attacher>;
        static BpfAttachManager& get_instance(){
            static BpfAttachManager manager;
            return manager;
        }

        AttacherPtr create_attacher(BpfProgramPtr prog, AttachSpec spec){
            lock_guard<mutex> lock(attacher_mutex_);
            auto attacher = make_shared<Attacher>(prog, spec, attachers_.size(), [this](int id){attacher_policy_change_process(id);});
            attachers_.push_back(attacher);
            return attachers;
        }

    private:
        std::mutex attacher_mutex_;
        std::mutex failed_request_mutex_;
        std::vector<AttacherPtr> attachers_;
        std::vector<AttachRequest> failed_requests_;
        std::atomic<std::uint64_t> generation_{0};
        
        BpfAttachManager();
        ~BpfAttachManager();

        void attacher_policy_change_process(int id);
    };
}

#endif