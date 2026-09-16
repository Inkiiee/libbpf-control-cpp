#ifndef BPF_ATTACHER_H
#define BPF_ATTACHER_H

#include <string>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <unordered_set>
#include <functional>

#include "bpf_tool/bpf_types.hpp"

namespace bpf_tool{
    enum class AttachMode{
        kAttachAll,
        kAttachSelective
    };

    using AttachModeType = std::atomic<AttachMode>;
    using FilterTargets = std::unordered_set<std::string>;

    struct Policy{
        std::unique_ptr<FilterTargets> policy;
        bool is_all;
        Policy(): policy{std::make_unique<FilterTargets>()}, is_all{false} {}
    };
    using PolicyPtr = std::shared_ptr<Policy>;

    class Attacher{
    public:
        using PolicyChangeCallback = std::function<void(int)>;

        Attacher(Attacher&&) = delete;
        Attacher& operator=(Attacher&&) = delete;
        Attacher(const Attacher&) = delete;
        Attacher& operator=(const Attacher&) = delete;

        Attacher(BpfProgramPtr prog, const AttachSpec spec, int id, PolicyChangeCallback callback);
        ~Attacher();

        void add_target(const std::string& nic_name);
        void remove_target(const std::string& nic_name);
        void clear_targets();
        PolicyPtr get_targets();

        void set_mode(AttachMode mode);
        AttachMode get_mode();

        BpfProgramPtr get_bpf_prog(){return prog_;}
        AttachSpec get_attach_spec(){return attach_spec_;}
    private:
        int id_;
        BpfProgramPtr prog_;
        AttachSpec attach_spec_;

        PolicyChangeCallback notify_change_policy_;
        AttachModeType mode_{AttachMode::kAttachSelective};
        FilterTargets target_nics_;
        PolicyPtr policy_snapshot_;
        std::mutex nics_list_mutex_;
        std::mutex snapshot_mutex_;

        void change_policy();
    };
}

#endif