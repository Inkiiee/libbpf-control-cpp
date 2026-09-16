#ifndef BPF_TYPES_HPP
#define BPF_TYPES_HPP

#include <cstdint>
#include <string>
#include <unistd.h>
#include <filesystem>
#include <system_error>

namespace bpf_tool{
    struct BpfProgram{
        std::uint32_t prog_id{0};
        bool is_pin_owner{false};
        int type;
        int fd;
        std::string function_name;
        std::string pinned_path;
        std::string section_name;

        BpfProgram(BpfProgram&&) = default;
        BpfProgram& operator=(BpfProgram&&) = default;
        BpfProgram(const BpfProgram&) = default;
        BpfProgram& operator=(const BpfProgram&) = default;
        BpfProgram():prog_id{0}, is_pin_owner{false}, type{-1}, fd{-1}{}

        ~BpfProgram(){
            if(fd >= 0) ::close(fd);

            if(!is_pin_owner) return;
            std::error_code ignore_ec;
            std::filesystem::path path(pinned_path);
            std::filesystem::remove(path, ignore_ec);
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