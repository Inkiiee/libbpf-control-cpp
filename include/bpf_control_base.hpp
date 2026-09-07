/*
Class Name   : bpf_control_base.hpp
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-07, 프로그램 작성
*/

#ifndef BPF_CONTROL_BASE_HPP
#define BPF_CONTROL_BASE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <memory>
#include <iostream>
#include <string_view>
#include <source_location>
#include <filesystem>
#include <system_error>

#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

namespace {
    // 디버그 모드 설정(true시에 로그 출력이 디버그 형태로 출력됨. false시에 로그 출력이 일반 형태로 출력됨)
    // 디버그 형식이란 로그 출력시 함수명, 파일명, 라인번호가 함께 출력되는 형태를 의미함.
    constexpr bool kDebugMode = true;
}

namespace bpf_control {
    enum class BpfControlErrorCode : std::uint32_t {
        kNoError = 0,
        kOpenError = 1,
        kNotOpenedError,
        kAlreadyOpenedError,
        kAlreadyPinnedError,
        kCloseError,
        kUpdateError,
        kLookupError,
        kDeleteError,
        kCreateMapError,
        kPinningError,
        kNotPinnedError,
        kUnpinningError,
        kGetNextKeyError,
        kGetNextKeyNotFoundError,
        kGetNextKeyInvalidError,
        kCallbackNotSetError,
        kBufferMakeError,
        kInvalidPerfPageSizeError,
        kInvalidPerfBufferSizeError,
        kInvalidRingBufferSizeError,
        kPerfFailedToGetCpuCountError,
        kPollingError,
    };

    inline constexpr std::string_view bpf_control_error_string(BpfControlErrorCode error_code) {
        switch (error_code) {
            case BpfControlErrorCode::kNoError:
                return "No error";
            case BpfControlErrorCode::kOpenError:
                return "Failed to open BPF object";
            case BpfControlErrorCode::kNotOpenedError:
                return "BPF object is not opened";
            case BpfControlErrorCode::kAlreadyOpenedError:
                return "BPF object is already opened";
            case BpfControlErrorCode::kAlreadyPinnedError:
                return "BPF object is already pinned";
            case BpfControlErrorCode::kCloseError:
                return "Failed to close BPF object";
            case BpfControlErrorCode::kUpdateError:
                return "Failed to update BPF map";
            case BpfControlErrorCode::kLookupError:
                return "Failed to lookup BPF map";
            case BpfControlErrorCode::kDeleteError:
                return "Failed to delete from BPF map";
            case BpfControlErrorCode::kCreateMapError:
                return "Failed to create BPF map";
            case BpfControlErrorCode::kPinningError:
                return "Failed to pin BPF object";
            case BpfControlErrorCode::kUnpinningError:
                return "Failed to unpin BPF object";
            case BpfControlErrorCode::kNotPinnedError:
                return "BPF object is not pinned"; 
            case BpfControlErrorCode::kGetNextKeyError:
                return "Failed to get next key from BPF map";
            case BpfControlErrorCode::kGetNextKeyNotFoundError:
                return "Next key not found in BPF map";
            case BpfControlErrorCode::kGetNextKeyInvalidError:
                return "Invalid key for getting next key from BPF map";
            case BpfControlErrorCode::kCallbackNotSetError:
                return "Callback function is not set for perf buffer";
            case BpfControlErrorCode::kBufferMakeError:
                return "Failed to make perf buffer";
            case BpfControlErrorCode::kInvalidPerfPageSizeError:
                return "Invalid perf page size specified";
            case BpfControlErrorCode::kInvalidPerfBufferSizeError:
                return "Invalid perf buffer size specified";
            case BpfControlErrorCode::kInvalidRingBufferSizeError:
                return "Invalid ring buffer size specified";
            case BpfControlErrorCode::kPerfFailedToGetCpuCountError:
                return "Failed to get CPU count for perf buffer";
            case BpfControlErrorCode::kPollingError:
                return "Polling error occurred in perf buffer";
            default:
                return "Unknown error code";
        }
    }

    inline std::string_view short_function_name(const char* function_name) noexcept {
        std::string_view name = function_name == nullptr ? std::string_view{} : function_name;
        if(const auto parameters = name.find('('); parameters != std::string_view::npos)
            name = name.substr(0, parameters);
        return name;
    }

    inline void log(
        std::string_view message,
        std::source_location location = std::source_location::current()) noexcept 
    {
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
    }

    class BpfBase{
    public:
        BpfBase(const std::string& n, const std::string& p) : fd_(-1), name_(n), pin_path_(p) {}
        virtual ~BpfBase(){ if(is_open()) close(); }

        virtual BpfControlErrorCode open(bool is_pinned = false, const std::string& pin_path = "") = 0;
        BpfControlErrorCode pin(const std::string& pin_path){
            if(!is_open()) return BpfControlErrorCode::kNotOpenedError;

            std::error_code ec;
            if(std::filesystem::exists(pin_path, ec))
                return BpfControlErrorCode::kAlreadyPinnedError;

            if(ec) {
                log("Error checking pin path existence: " + ec.message());
                return BpfControlErrorCode::kPinningError;
            }

            if(bpf_obj_pin(fd_, pin_path.c_str()) < 0) 
                return BpfControlErrorCode::kPinningError;

            this->pin_path_ = pin_path;
            return BpfControlErrorCode::kNoError;
        }
        virtual BpfControlErrorCode close(){
            if(!is_open()) return BpfControlErrorCode::kNotOpenedError;

            if(::close(fd_) < 0) 
                return BpfControlErrorCode::kCloseError;
            
            fd_ = -1;
            return BpfControlErrorCode::kNoError;
        }
        BpfControlErrorCode unpin(){
            if(!is_open()) return BpfControlErrorCode::kNotOpenedError;

            std::error_code ec;
            if(std::filesystem::exists(pin_path_, ec)){
                std::filesystem::remove(pin_path_, ec);
                if(ec){
                    log("Error unpinning map: " + ec.message());
                    return BpfControlErrorCode::kUnpinningError; // Failed to unpin the map
                }

                pin_path_.clear(); // Clear the pin path
                return BpfControlErrorCode::kNoError;
            }

            if(ec){
                log("Error checking pin path existence: " + ec.message());
                pin_path_.clear(); // Clear the pin path
                return BpfControlErrorCode::kUnpinningError; // Error checking pin path existence
            }

            pin_path_.clear(); // Clear the pin path
            return BpfControlErrorCode::kNotPinnedError;
        }

        bool is_open() const { return fd_ >= 0; }
        int get_fd() const { return fd_; }
        std::string get_name() const { return name_; }
        std::string get_pin_path() const { return pin_path_; }
    protected:
        int fd_ = -1;
        std::string name_;
        std::string pin_path_;
    };
};

#endif // BPF_CONTROL_BASE_HPP