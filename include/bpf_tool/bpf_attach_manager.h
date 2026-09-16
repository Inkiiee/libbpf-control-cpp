#ifndef BPF_ATTACH_MANAGER_H
#define BPF_ATTACH_MANAGER_H

#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <condition_variable>
#include <chrono>

#include "bpf_tool/bpf_types.hpp"
#include "bpf_tool/bpf_attacher.h"
#include "nic_check/interface_loader.h"

namespace bpf_tool{
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    struct ApplyRequest{
        int id;
        int retry_count;
        bool is_immediate;
        TimePoint request_time;

        ApplyRequest(ApplyRequest&& other)
            : id{other.id}, retry_count{other.retry_count}, is_immediate{other.is_immediate}, request_time{other.request_time} {}
        ApplyRequest(const ApplyRequest& other)
            : id{other.id}, retry_count{other.retry_count}, is_immediate{other.is_immediate}, request_time{other.request_time} {}
        explicit ApplyRequest(int i, bool is = false, int r = 0)
            : id{i}, retry_count{r}, is_immediate{is}, request_time{Clock::now()} {}

        ApplyRequest& operator=(ApplyRequest&& other){
            id = other.id;
            request_time = other.request_time;
            retry_count = other.retry_count;
            is_immediate = other.is_immediate;
            return *this;
        }
        ApplyRequest& operator=(const ApplyRequest& other){
            id = other.id;
            request_time = other.request_time;
            retry_count = other.retry_count;
            is_immediate = other.is_immediate;
            return *this;
        }
        bool operator==(const ApplyRequest& other) const {
            return id == other.id;
        }
    };
    struct ApplyRequestHash {
        std::size_t operator()(const ApplyRequest& request) const noexcept {
            return std::hash<int>{}(request.id);
        }
    };

    using ApplyRequestQueue = std::unordered_set<ApplyRequest, ApplyRequestHash>;

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
        ApplyRequestQueue apply_requests_;

        BpfAttachManager();
        ~BpfAttachManager();

        void attacher_policy_change_process(int id);
        void append_apply_request(ApplyRequest request);

        bool apply_targets_policy_per_attacher(ApplyRequest request);
        bool is_attach_filter(const std::string& nic_name, BpfProgramPtr prog, AttachSpec spec);
        bool attach_filter(const std::string& nic_name, BpfProgramPtr prog, AttachSpec spec);
        bool detach_filter(const std::string& nic_name, BpfProgramPtr prog, AttachSpec spec);
    };
}

#endif