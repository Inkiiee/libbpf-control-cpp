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

#include "utils/logger.hpp"

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
        kInvalidUnpinError,
        kBpfRuntimeInitError
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
            case BpfControlErrorCode::kInvalidUnpinError:
                return "The Pin path is not allow remove cause the object is not pin file's owner";
            case BpfControlErrorCode::kBpfRuntimeInitError:
                return "Bpf runtime strict mode set error";
            default:
                return "Unknown error code";
        }
    }

    class BpfBase{
    public:
        BpfBase() = delete;
        BpfBase(const BpfBase&) = delete;
        BpfBase& operator=(const BpfBase&) = delete;

        BpfBase(BpfBase&& other) noexcept
            : fd_(std::exchange(other.fd_, -1)), name_(std::move(other.name_)), pin_path_(std::move(other.pin_path_)), is_pin_owner_(other.is_pin_owner_) {
                other.is_pin_owner_ = false;
            }
        BpfBase& operator=(BpfBase&& other) noexcept {
            if (this != &other) {
                if (is_open()) close();
                fd_ = std::exchange(other.fd_, -1);
                name_ = std::move(other.name_);
                pin_path_ = std::move(other.pin_path_);
                is_pin_owner_ = other.is_pin_owner_;
                other.is_pin_owner_ = false;
            }
            return *this;
        }

        BpfBase(const std::string& n, const std::string& p) : fd_(-1), name_(n), pin_path_(p) {}
        virtual ~BpfBase(){ if(is_open()) close(); }

        virtual BpfControlErrorCode open(bool is_pinned = false, const std::string& pin_path = "") = 0;
        BpfControlErrorCode pin(const std::string& pin_path){
            if(!is_open()) return BpfControlErrorCode::kNotOpenedError;

            std::error_code ec;
            if(std::filesystem::exists(pin_path, ec))
                return BpfControlErrorCode::kAlreadyPinnedError;

            if(ec) {
                utils::log("Error checking pin path existence: " + ec.message());
                return BpfControlErrorCode::kPinningError;
            }

            if(bpf_obj_pin(fd_, pin_path.c_str()) < 0) 
                return BpfControlErrorCode::kPinningError;

            this->pin_path_ = pin_path;
            this->is_pin_owner_ = true;
            return BpfControlErrorCode::kNoError;
        }
        virtual BpfControlErrorCode close(){
            if(!is_open()) return BpfControlErrorCode::kNotOpenedError;

            BpfControlErrorCode error = BpfControlErrorCode::kNoError;
            if(::close(fd_) < 0)  // Linux에서 ::close()는 반환값과 무관하게 fd를 항상 해제합니다. (중요.)
                error = BpfControlErrorCode::kCloseError;
                
            
            // close는 기본적으로 소유권을 버리는 행위로 봄.
            // Map은 기본적으로는 pin된 맵을 정리하지 않음.
            // 소유권이 있더라도 프로그램 종료 -> pinned map 제거로 이어지지 않음.
            // 이유는 간단하게 말해서, pin을 한 순간 프로그램이 종료되어도 유지되어야할 내용을 map에 넣었다고 가정함.
            is_pin_owner_ = false;
            pin_path_.clear();
            fd_ = -1;
            return error;
        }
        BpfControlErrorCode unpin(){
            if(!is_open()) return BpfControlErrorCode::kNotOpenedError;

            if(!is_pin_owner_)
                return BpfControlErrorCode::kInvalidUnpinError;

            // unpin을 선언한 순간 이미 소유권을 버린걸로 본다.
            // 실제 삭제에 문제가 생긴 경우에만 복구하는걸로 한정함.
            is_pin_owner_ = false;

            std::error_code ec;
            if(std::filesystem::exists(pin_path_, ec)){
                std::filesystem::remove(pin_path_, ec);
                if(ec){
                    is_pin_owner_ = true; // 삭제에 문제가 있다면 아직 남은거니 소유권을 다시 돌려준다.
                    utils::log("Error unpinning map: " + ec.message());
                    return BpfControlErrorCode::kUnpinningError; // Failed to unpin the map
                }

                pin_path_.clear(); // Clear the pin path
                return BpfControlErrorCode::kNoError;
            }

            if(ec){
                utils::log("Error checking pin path existence: " + ec.message());
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
        bool is_pin_owner_{false};
    };
};

#endif // BPF_CONTROL_BASE_HPP