#ifndef BPF_PROG_LOADER_H
#define BPF_PROG_LOADER_H

#include <string>
#include <utility>
#include <vector>
#include <memory>

#include "bpf_tool/bpf_types.hpp"
#include "bpf_map_control/bpf_control_base.hpp"

namespace bpf_tool{
    enum class BpfProgLoaderError{
        kNoError = 0,
        kUploadProgToKernelError = 1,
        kLoadProgObjectError,
        kSetProgTypeError,
        kProgDontUseTheBpfMapError,
        kInvalidBpfMapPinPathError,
        kProgPinError,
        kGetProgFdError,
        kGetProgIdError,
    };
    class BpfProgLoader{
    public:
        using BpfProgramPtrAndError = std::pair<BpfProgramPtr, BpfProgLoaderError>
        static BpfProgramPtrAndError load_program(
            const std::string& prog_obj_path, const std::string& function_name, int type=BPF_PROG_TYPE_SCHED_CLS,
            const std::string& pin_dir="/sys/fs/bpf/", const std::vector<bpf_control::BpfBase*>& pinned_maps);
    private:
        BpfProgLoader(const BpfProgLoader&) = delete;
        BpfProgLoader(BpfProgLoader&&) = delete;
        BpfProgLoader& operator=(const BpfProgLoader&) = delete;
        BpfProgLoader& operator=(BpfProgLoader&&) = delete;
        BpfProgLoader(){}
        ~BpfProgLoader(){}
    };
}

#endif