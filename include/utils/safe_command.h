/*
Class Name   : safe_command.h
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-09, 프로그램 작성
*/

#ifndef SAFE_COMMAND_H
#define SAFE_COMMAND_H

#include <string_view>
#include <vector>
#include <string>

#include "utils/logger.hpp"

namespace utils{
    enum class SafeCommandError {
        kNoError = 0,
        kSpawnError = -1,
        kWaitError = -2,
        kReturnError = -3,
        kFileActionsError = -4,
        kActionsInitError = -5,
        kFileActionsAddError = -6,
        kFileActionsDestroyError = -7,
    };
    
    inline constexpr std::string_view safe_system_error_string(SafeCommandError error) noexcept {
        switch (error) {
            case SafeCommandError::kNoError: return "No error";
            case SafeCommandError::kSpawnError: return "Failed to posix spawnp for the system command";
            case SafeCommandError::kWaitError: return "Failed to wait for the system command";
            case SafeCommandError::kReturnError: return "System command returned an error";
            case SafeCommandError::kFileActionsError: return "Failed to perform file actions";
            case SafeCommandError::kActionsInitError: return "Failed to initialize file actions";
            case SafeCommandError::kFileActionsAddError: return "Failed to add file actions";
            case SafeCommandError::kFileActionsDestroyError: return "Failed to destroy file actions";
            default: return "Unrecognized error code";
        }
    }

    class SafeCommand {
    public:
        // 사용법, 사용할 명령어를 argv 배열로 전달하고, exit_status를 통해 자식 프로세스의 종료 상태를 반환합니다.
        // 리턴 값은 kNoError, kSpawnError, kWaitError, kReturnError 중 하나입니다.
        // 예: char* argv[] = {"ls", "-l", NULL}; int exit_status; safe_system(argv, &exit_status);
        static SafeCommandError safe_command(char* const argv[], int* exit_status);
        // silent error 버전, stderr를 /dev/null로 리다이렉트하여 에러 메시지를 숨깁니다.
        static SafeCommandError safe_command_silent_error(char* const argv[], int* exit_status);
        // 추후에 파일 디스크립터를 리다이렉트한다던지, 파일 액션을 추가할 수 있는 확장성을 고려하여 필요시 추가.

        static SafeCommandError run_command(const std::vector<std::string>& args, bool silent_error = false);

        // 유효성 검사, 유효하면 1, 유효하지 않으면 0을 반환합니다.
        // 유효한 IP 주소인지 확인합니다. (IPv4만 지원)
        static bool check_valid_ip(const char* ip);
        // 유효한 인터페이스 이름인지 확인합니다. (영문 소문자, 숫자, 밑줄만 허용, 길이 1~15)
        static bool check_valid_ifname(const char* ifname);
        // 유효한 포트 번호인지 확인합니다. (1~65535)
        static bool check_valid_port(const char* port_str);
    private:
        SafeCommand(const SafeCommand&) = delete; // Delete copy constructor
        SafeCommand& operator=(const SafeCommand&) = delete; // Delete copy assignment operator
        SafeCommand() = default; // Private constructor to prevent instantiation
        ~SafeCommand() = default; // Private destructor to prevent instantiation
    };
}

#endif //SAFE_COMMAND_H