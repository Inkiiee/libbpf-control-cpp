#include "test_support.hpp"

#include <cerrno>
#include <memory>

#include <fcntl.h>
#include <unistd.h>

#include "bpf_tool/bpf_types.hpp"

using namespace bpf_tool;

namespace{
    bool has_safe_default_state(){
        BpfProgram program;

        TEST_CHECK(program.prog_id == 0);
        TEST_CHECK(program.type == -1);
        TEST_CHECK(program.fd == -1);

        return true;
    }

    bool closes_owned_fd_after_last_reference(){
        int pipe_fds[2]{};
        TEST_CHECK(::pipe(pipe_fds) == 0);

        const int owned_fd = pipe_fds[0];
        const int peer_fd = pipe_fds[1];

        {
            auto program = std::make_shared<BpfProgram>();
            program->fd = owned_fd;

            auto second_reference = program;
            program.reset();

            TEST_CHECK(::fcntl(owned_fd, F_GETFD) != -1);
            second_reference.reset();
        }

        errno = 0;
        TEST_CHECK(::fcntl(owned_fd, F_GETFD) == -1);
        TEST_CHECK(errno == EBADF);
        TEST_CHECK(::close(peer_fd) == 0);

        return true;
    }
}

int main(){
    return test_support::run({
        {"BpfProgram has a safe default state", has_safe_default_state},
        {"BpfProgram closes its owned FD", closes_owned_fd_after_last_reference}
    });
}
