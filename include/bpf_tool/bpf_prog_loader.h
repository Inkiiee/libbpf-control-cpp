#ifndef BPF_PROG_LOADER_H
#define BPF_PROG_LOADER_H

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "bpf_map_control/bpf_control_base.hpp"
#include "bpf_tool/bpf_types.hpp"

namespace bpf_tool{
    enum class BpfProgLoaderError{
        kNoError = 0,
        kUploadProgToKernelError = 1,
        kLoadProgObjectError,
        kSetProgTypeError,
        kProgDontUseTheBpfMapError,
        kReuseMapError,
        kBpfProgFailedMapLoad,
        kGetProgFdError,
        kGetProgIdError,
        kBpfRuntimeInitError,
    };
    class BpfProgLoader{
    public:
        using BpfProgramPtrAndError = std::pair<BpfProgramPtr, BpfProgLoaderError>;
        static BpfProgramPtrAndError load_program(
            const std::string& prog_obj_path, const std::string& function_name,
            const std::vector<bpf_control::BpfBase*>& bpf_maps,
            int type=BPF_PROG_TYPE_SCHED_CLS);
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
