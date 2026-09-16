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
        kBpfProgFailedPinnedMapLoad,
        kGetProgFdError,
        kGetProgIdError,
    };
    class BpfProgLoader{
    public:
        using BpfProgramPtrAndError = std::pair<BpfProgramPtr, BpfProgLoaderError>;
        static BpfProgramPtrAndError load_program(
            const std::string& prog_obj_path, const std::string& function_name, 
            const std::vector<bpf_control::BpfBase*>& pinned_maps,
            const std::string& pin_dir="/sys/fs/bpf/", int type=BPF_PROG_TYPE_SCHED_CLS);
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