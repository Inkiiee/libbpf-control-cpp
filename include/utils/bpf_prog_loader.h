/*
Class Name   : bpf_prog_loader.h
@version     : 1.2
@author      : Inkiiee
@modify      : 2026-09-09, 프로그램 작성
               2026-09-14, pin한 파일에 대한 소유권 명시 및 set_pin_path를 bpf_reuse_fd로 수정
*/

#ifndef BPF_PROG_LOADER_H
#define BPF_PROG_LOADER_H

#include <string>
#include <string_view>
#include <cstdint>
#include <optional>
#include <vector>

#include "nic_check/interface_loader.h"
#include "bpf_control_base.hpp"

namespace utils{
    enum class BpfProgLoaderError: std::uint32_t {
        kNoError = 0,
        kVerifierError = 1,
        kProgObjectNotExistsError,
        kBpfFunctionNameNotFoundError,
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
        kGetProgIdError
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
    private:
        std::string prog_obj_path_;
        std::string pinned_prog_path_;
        nic_check::InterfaceLoader loader;
        int handle_;
        int priority_;
        bool is_ingress_;
        bool is_owner_of_the_pin_;
        std::optional<std::uint32_t> prog_id_;

        BpfProgLoaderError load_and_pin_prog_obj(const std::string& function_name, const std::vector<bpf_control::BpfBase*>& pinned_maps);
        BpfProgLoaderError attach_to_interfaces(nic_check::InterfaceLoader::SnapshotPtr interfaces);
    };
}

#endif
