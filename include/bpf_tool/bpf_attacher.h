#ifndef BPF_ATTACHER_H
#define BPF_ATTACHER_H

#include <string>
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

    using FilterTargets = std::unordered_set<std::string>;

    struct PolicyType{
        FilterTargets policy;
        bool is_all;
        PolicyType(): policy{}, is_all{false} {}
        PolicyType(const FilterTargets& p, bool all): policy{p}, is_all{all} {}
    };
    using PolicyPtr = std::shared_ptr<const PolicyType>;

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
        AttachMode mode_{AttachMode::kAttachSelective};
        FilterTargets target_nics_;
        PolicyPtr policy_snapshot_;
        std::mutex nics_list_mutex_;

        void change_policy();
    };
}

#endif