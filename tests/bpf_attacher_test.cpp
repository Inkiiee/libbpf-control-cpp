#include "test_support.hpp"

#include <memory>

#include "bpf_tool/bpf_attacher.h"

using namespace bpf_tool;

namespace{
    bool updates_selective_policy(){
        auto program = std::make_shared<BpfProgram>();
        int callback_count = 0;
        int notified_id = -1;

        Attacher attacher{
            program,
            AttachSpec{.priority = 10, .handle = 20, .is_ingress = false},
            37,
            [&](int id){
                ++callback_count;
                notified_id = id;
            }
        };

        const auto initial_policy = attacher.get_targets();
        TEST_CHECK(initial_policy != nullptr);
        TEST_CHECK(!initial_policy->is_all);
        TEST_CHECK(initial_policy->policy.empty());

        attacher.add_target("eth0");
        TEST_CHECK(callback_count == 1);
        TEST_CHECK(notified_id == 37);

        const auto first_policy = attacher.get_targets();
        TEST_CHECK(first_policy->policy.size() == 1);
        TEST_CHECK(first_policy->policy.contains("eth0"));

        attacher.add_target("eth0");
        attacher.remove_target("missing0");
        TEST_CHECK(callback_count == 1);

        attacher.add_target("eth1");
        TEST_CHECK(callback_count == 2);

        const auto second_policy = attacher.get_targets();
        TEST_CHECK(second_policy->policy.size() == 2);
        TEST_CHECK(second_policy->policy.contains("eth0"));
        TEST_CHECK(second_policy->policy.contains("eth1"));

        TEST_CHECK(first_policy->policy.size() == 1);
        TEST_CHECK(!first_policy->policy.contains("eth1"));

        attacher.remove_target("eth0");
        TEST_CHECK(callback_count == 3);
        TEST_CHECK(!attacher.get_targets()->policy.contains("eth0"));

        attacher.clear_targets();
        TEST_CHECK(callback_count == 4);
        TEST_CHECK(attacher.get_targets()->policy.empty());

        attacher.clear_targets();
        TEST_CHECK(callback_count == 4);

        return true;
    }

    bool updates_attach_mode(){
        auto program = std::make_shared<BpfProgram>();
        int callback_count = 0;

        Attacher attacher{
            program,
            AttachSpec{},
            1,
            [&](int){ ++callback_count; }
        };

        TEST_CHECK(attacher.get_mode() == AttachMode::kAttachSelective);

        attacher.set_mode(AttachMode::kAttachAll);
        TEST_CHECK(callback_count == 1);
        TEST_CHECK(attacher.get_mode() == AttachMode::kAttachAll);
        TEST_CHECK(attacher.get_targets()->is_all);

        attacher.set_mode(AttachMode::kAttachAll);
        TEST_CHECK(callback_count == 1);

        attacher.set_mode(AttachMode::kAttachSelective);
        TEST_CHECK(callback_count == 2);
        TEST_CHECK(!attacher.get_targets()->is_all);

        return true;
    }

    bool invokes_callback_outside_internal_lock(){
        auto program = std::make_shared<BpfProgram>();
        Attacher* attacher_pointer = nullptr;
        PolicyPtr policy_observed_by_callback;

        Attacher attacher{
            program,
            AttachSpec{},
            2,
            [&](int){ policy_observed_by_callback = attacher_pointer->get_targets(); }
        };
        attacher_pointer = &attacher;

        attacher.add_target("eth0");

        TEST_CHECK(policy_observed_by_callback != nullptr);
        TEST_CHECK(policy_observed_by_callback->policy.contains("eth0"));

        return true;
    }

    bool accepts_an_empty_callback(){
        auto program = std::make_shared<BpfProgram>();
        Attacher attacher{program, AttachSpec{}, 3, {}};

        attacher.add_target("eth0");
        attacher.set_mode(AttachMode::kAttachAll);

        TEST_CHECK(attacher.get_targets()->is_all);
        TEST_CHECK(attacher.get_bpf_prog() == program);
        TEST_CHECK(attacher.get_attach_spec().priority == 100);

        return true;
    }
}

int main(){
    return test_support::run({
        {"updates selective policy", updates_selective_policy},
        {"updates attach mode", updates_attach_mode},
        {"callback runs outside internal lock", invokes_callback_outside_internal_lock},
        {"empty callback is allowed", accepts_an_empty_callback}
    });
}
