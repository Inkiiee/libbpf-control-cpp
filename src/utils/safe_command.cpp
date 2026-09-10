/*
Class Name   : safe_command.cpp
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-09, 프로그램 작성
*/

// Makes safe_system tolerate NULL exit_status callers in relay-server helpers.
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstdlib>
#include <arpa/inet.h>
#include <net/if.h>
#include <sstream>

#include "utils/safe_command.h"

extern char **environ; // 리눅스에서 환경 변수를 가져오는 전역 변수(필수, 지우면 안됨)

using namespace utils;

namespace {
    bool wait_for_child(pid_t pid, int& status) {
        pid_t wait_result = -1;
        do {
            wait_result = waitpid(pid, &status, 0);
        } while (wait_result < 0 && errno == EINTR);

        return wait_result == pid;
    }
}

// safe_command 함수, system함수 대용. (code injection 취약점 방지, exit_status NULL 허용)
utils::SafeCommandError utils::SafeCommand::safe_command(char* const argv[], int* exit_status)
{
    pid_t pid;
    int status;
    int local_exit_status = -1;
    int *status_out = exit_status ? exit_status : &local_exit_status;

    *status_out = -1; // Initialize exit_status to an invalid value
    if(posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ) != 0) {
        return SafeCommandError::kSpawnError; // Failed to spawn process
    }

    if(!wait_for_child(pid, status)) {
        return SafeCommandError::kWaitError; // Failed to wait for child process
    }

    if(WIFEXITED(status)) {
        *status_out = WEXITSTATUS(status);
        return SafeCommandError::kNoError; // Return the exit status of the child process
    }

    return SafeCommandError::kReturnError; // Child process did not terminate normally
}

// safe_command와 동일하지만 stderr를 /dev/null로 리다이렉트하여 에러 메시지를 숨깁니다.
utils::SafeCommandError utils::SafeCommand::safe_command_silent_error(char* const argv[], int* exit_status)
{
    pid_t pid;
    int status;
    int rc;
    int local_exit_status = -1;
    int *status_out = exit_status ? exit_status : &local_exit_status;

    posix_spawn_file_actions_t actions; // posix_spawn의 경우에는 파일 디스크립터를 리다이렉트 가능하고 그것을 요청하기 위한 구조체
    rc = posix_spawn_file_actions_init(&actions); // 사용전 필수로 초기화해야 함
    if(rc != 0) {
        return SafeCommandError::kActionsInitError; // Failed to initialize file actions
    }

    // stderr를 /dev/null로 리다이렉트
    rc = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    if(rc != 0) {
        posix_spawn_file_actions_destroy(&actions); // 반드시 init을 했다면 destroy를 호출해야 함
        return SafeCommandError::kFileActionsAddError; // Failed to add file action
    }

    *status_out = -1; // Initialize exit_status to an invalid value
    if(posix_spawnp(&pid, argv[0], &actions, NULL, argv, environ) != 0) {
        posix_spawn_file_actions_destroy(&actions); // 반드시 init을 했다면 destroy를 호출해야 함
        return SafeCommandError::kFileActionsError; // Failed to spawn process with file actions
    }

    posix_spawn_file_actions_destroy(&actions); // 반드시 init을 했다면 destroy를 호출해야 함
    if(!wait_for_child(pid, status)) {
        return SafeCommandError::kWaitError; // Failed to wait for child process
    }

    if(WIFEXITED(status)) {
        *status_out = WEXITSTATUS(status); // Return the exit status of the child process
        return SafeCommandError::kNoError; // Return the exit status of the child process
    }

    return SafeCommandError::kReturnError; // Child process did not terminate normally
}

utils::SafeCommandError utils::SafeCommand::run_command(const std::vector<std::string>& args, bool silent_error){
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);

    for(const auto& arg: args)
        argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);

    int exit_status = -1;
    const auto err = silent_error
        ? SafeCommand::safe_command_silent_error(argv.data(), &exit_status)
        : SafeCommand::safe_command(argv.data(), &exit_status);

    if(err != SafeCommandError::kNoError || exit_status != 0) {
        std::ostringstream oss;
        oss << "command failed:";
        for (const auto& arg : args)
            oss << ' ' << arg;
        oss << " exit=" << exit_status;
        utils::log(oss.str());
        return err == SafeCommandError::kNoError ? SafeCommandError::kReturnError : err;
    }

    return err;
}

// 유효성 검사, 유효하면 true, 유효하지 않으면 false를 반환합니다.
bool utils::SafeCommand::check_valid_ip(const char* ip){
    if(ip == nullptr || *ip == '\0')
        return false; // Invalid if null or empty

    struct in_addr addr;
    int ret = inet_pton(AF_INET, ip, &addr);
    return ret == 1; // Valid IPv4 address if inet_pton returns 1
}
// interface 이름의 유효성을 검사합니다. (영문 소문자, 숫자, 밑줄만 허용, 길이 1~15)
// 유효성 검사, 유효하면 true, 유효하지 않으면 false를 반환합니다.
bool utils::SafeCommand::check_valid_ifname(const char* ifname){
    if(ifname == nullptr || *ifname == '\0')
        return false; // Invalid if null or empty

    unsigned int index = if_nametoindex(ifname);
    return index != 0; // Valid interface name if index is non-zero
}
// 포트 번호의 유효성을 검사합니다. (1~65535)
// 유효성 검사, 유효하면 true, 유효하지 않으면 false를 반환합니다.
bool utils::SafeCommand::check_valid_port(const char* port_str){
    if(port_str == nullptr || *port_str == '\0')
        return false; // Invalid if null or empty

    char* end = nullptr;
    errno = 0;

    long port = std::strtol(port_str, &end, 10);

    if (errno == ERANGE)
        return false;

    // 숫자를 하나도 못 읽었거나, 뒤에 다른 문자가 남음
    if (end == port_str || *end != '\0')
        return false;

    return port >= 1 && port <= 65535;
}
