/*
Class Name   : logger.hpp
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-07, 프로그램 작성
*/

#ifndef LOGGER_H
#define LOGGER_H

#include <string_view>
#include <filesystem>
#include <iostream>
#include <source_location>
#include <mutex>

namespace utils{
    // 디버그 모드 설정(true시에 로그 출력이 디버그 형태로 출력됨. false시에 로그 출력이 일반 형태로 출력됨)
    // 디버그 형식이란 로그 출력시 함수명, 파일명, 라인번호가 함께 출력되는 형태를 의미함.
    constexpr bool kDebugMode = true;
    inline std::mutex log_mutex;

    inline std::string_view short_function_name(const char* function_name) noexcept {
        std::string_view name = function_name == nullptr ? std::string_view{} : function_name;
        if(const auto parameters = name.find('('); parameters != std::string_view::npos)
            name = name.substr(0, parameters);
        return name;
    }

    // noexcept 를 유지하기 위해 본문 전체를 감싼다.
    // lock_guard 의 lock() 과 스트림 출력 모두 던질 수 있고,
    // noexcept 함수(예: interface_loader 의 noexcept 헬퍼들)에서 호출되므로
    // 여기서 새어나가면 곧바로 std::terminate 이다.
    // 로그를 못 남기는 것보다 프로세스가 죽는 쪽이 나쁘므로 삼킨다.
    inline void log(
        std::string_view message,
        std::source_location location = std::source_location::current()) noexcept
    {
        try{
            std::lock_guard<std::mutex> lock(log_mutex);

            if constexpr (kDebugMode) {
                try{
                    std::filesystem::path file_path(location.file_name());
                    auto file_name = file_path.filename().string();
                    std::cerr << "[DEBUG] " << file_name << ":" << location.line() << " (" << short_function_name(location.function_name()) << ") - " << message << std::endl;
                } catch (const std::exception& e) {
                    std::cerr << "[DEBUG] " << location.file_name() << ":" << location.line() << " (" << short_function_name(location.function_name()) << ") - " << message << std::endl;
                }
            } else {
                std::cerr << message << std::endl;
            }
        } catch(...) {
            // 로그 실패는 무시한다.
        }
    }
}

#endif //LOGGER_H
