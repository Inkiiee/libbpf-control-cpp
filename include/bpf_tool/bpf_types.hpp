#ifndef BPF_TYPES_HPP
#define BPF_TYPES_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <unistd.h>

namespace bpf_tool{
    struct BpfProgram{
        std::uint32_t prog_id{0};
        int type;
        int fd;
        std::string function_name;
        std::string section_name;

        BpfProgram(BpfProgram&&) = delete;
        BpfProgram& operator=(BpfProgram&&) = delete;
        BpfProgram(const BpfProgram&) = delete;
        BpfProgram& operator=(const BpfProgram&) = delete;
        BpfProgram():prog_id{0}, type{-1}, fd{-1}{}

        ~BpfProgram(){
            if(fd >= 0) ::close(fd);
        }
    };

    using BpfProgramPtr = std::shared_ptr<BpfProgram>;

    struct AttachSpec{
        int priority{100};
        int handle{1};
        bool is_ingress{true};
    };

    enum class BpfAttachOp{
        kAttach = 0,
        kDetach = 1
    };
}

#endif
