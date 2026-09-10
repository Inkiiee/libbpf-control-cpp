/*
Class Name   : bpf_prog_loader.h
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-09, 프로그램 작성
*/

#ifndef BPF_PROG_LOADER_H
#define BPF_PROG_LOADER_H

#include <string>
#include <string_view>
#include <cstdint>
#include <vector>

#include "nic_check/interface_loader.h"

namespace utils{
    enum class BpfProgLoaderError: std::uint32_t {
        kNoError = 0,
        kVerifierError = 1,
        kAlreadyExistsError = 2,
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
    };

    class BpfProgLoader{
    public:
        BpfProgLoader(const BpfProgLoader&) = delete;
        BpfProgLoader(BpfProgLoader&&) = delete;
        BpfProgLoader& operator=(const BpfProgLoader&) = delete;
        BpfProgLoader& operator=(BpfProgLoader&&) = delete;

        BpfProgLoader(const std::string& prog_path);
        ~BpfProgLoader();

        BpfProgLoaderError load_prog(const std::string& function_name, const std::vector<std::string>& pinned_map_names);
    private:
        std::string prog_obj_path_;
        std::string pinned_prog_path_;
        nic_check::InterfaceLoader loader;
    };
}

#endif