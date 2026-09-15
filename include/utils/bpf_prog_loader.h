/*
Class Name   : bpf_prog_loader.h
@version     : 1.3
@author      : Inkiiee
@modify      : 2026-09-09, 프로그램 작성
               2026-09-14, pin한 파일에 대한 소유권 명시 및 set_pin_path를 bpf_reuse_fd로 수정
               2026-09-14, 필터 부착 인터페이스 필터 추가 및 자동 재시도 기능 추가
*/

#ifndef BPF_PROG_LOADER_H
#define BPF_PROG_LOADER_H

#include <string>
#include <string_view>
#include <cstdint>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <atomic>
#include <optional>

#include "nic_check/interface_loader.h"
#include "bpf_control_base.hpp"

namespace utils{
    enum class BpfProgLoaderError: std::uint32_t {
        kNoError = 0,
        kVerifierError = 1,
        kProgObjectNotExistsError,
        kBpfProgPinError,
        kBpfObjectOpenFailed,
        kBpfProgDontUseTheMap,
        kBpfProgFailedPinnedMapLoad,
        kBpfNotExistsThePinnedMap,
        kQdiscFailedError,
        kBpfAttachError,
        kProgGetFdError,
        kBpfDetachError,
        kInterfaceMonitorFailed,
        kGetProgIdError,
    };

    class BpfProgLoader{
    public:
        BpfProgLoader(const BpfProgLoader&) = delete;
        BpfProgLoader(BpfProgLoader&&) = delete;
        BpfProgLoader& operator=(const BpfProgLoader&) = delete;
        BpfProgLoader& operator=(BpfProgLoader&&) = delete;

        BpfProgLoader(const std::string& prog_path, int handle = 1, int priority = 100, bool is_ingress = true);
        ~BpfProgLoader();

        BpfProgLoaderError load_prog(const std::string& function_name, const std::vector<bpf_control::BpfBase*>& pinned_maps);

        // nic 필터 추가. 단 해당 필터는 비어있으면 전체 통과.
        void add_target_nic(const std::string& target_ifname);
        void remove_target_nic(const std::string& target_ifname);
        void clear_target_nics();
        std::vector<std::string> get_all_target_nics();
    private:
        std::string prog_obj_path_;
        std::string pinned_prog_path_;
        nic_check::InterfaceLoader loader;
        int handle_;
        int priority_;
        int prog_id_;
        bool is_ingress_;
        bool is_owner_of_the_pin_;

        std::mutex failed_nics_mutex_;
        std::mutex target_nics_mutex_;
        std::unordered_set<std::string> failed_nics_;
        std::unordered_set<std::string> target_nics_;
        std::jthread attach_recovery_thread_;
        std::atomic<bool> has_failed_filter_{false};

        BpfProgLoaderError load_and_pin_prog_obj(const std::string& function_name, const std::vector<bpf_control::BpfBase*>& pinned_maps);
        std::optional<bool> is_applied_filter(int ifindex);
        std::optional<bool> is_applied_filter_by_ifname(const std::string& ifname);
        void attach_filters(nic_check::InterfaceLoader::SnapshotPtr snaps);
        BpfProgLoaderError attach_filter(int ifindex);
        BpfProgLoaderError attach_filter_by_ifname(const std::string& ifname);
        BpfProgLoaderError detach_filter(int ifindex);
        BpfProgLoaderError detach_filter_by_ifname(const std::string& ifname);
    };
}

#endif