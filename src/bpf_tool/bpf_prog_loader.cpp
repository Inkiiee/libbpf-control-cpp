#include "bpf_tool/bpf_prog_loader.h"
#include "utils/logger.hpp"

#include <filesystem>
#include <system_error>
#include <string_view>
#include <optional>
#include <memory>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <errno.h>

using namespace std;
using namespace bpf_control;
using namespace bpf_tool;
using namespace utils;
namespace fs = std::filesystem;

namespace{
    bool is_exists_file(const fs::path& file_path) noexcept {
        error_code err_code;
        if(fs::exists(file_path, err_code))
            return true;

        if(err_code)
            utils::log("file exists check error: " + err_code.message());

        return false;
    }

    bool make_directory_if_not_exist(const fs::path& dir_path) noexcept {
        error_code ec;
        fs::create_directories(dir_path, ec);
        if(ec){
            utils::log("create directory " + dir_path.string() + " failed: " + ec.message());
            return false;
        }
        return true;
    }

    bool is_correct_bpf_prog_type(int type){
        switch(type){
            // 네트워크 관련 타입
            case BPF_PROG_TYPE_SCHED_CLS: //분류기
            case BPF_PROG_TYPE_SCHED_ACT: //구형 호환성용
            case BPF_PROG_TYPE_XDP:
            case BPF_PROG_TYPE_SOCKET_FILTER:

            // 모니터링/관측 관련 타입
            case BPF_PROG_TYPE_KPROBE:
            case BPF_PROG_TYPE_TRACEPOINT:
            case BPF_PROG_TYPE_RAW_TRACEPOINT:

            // 보안 및 소켓 관리 관련 타입
            case BPF_PROG_TYPE_LSM:
            case BPF_PROG_TYPE_SOCK_OPS:
            case BPF_PROG_TYPE_CGROUP_SKB:
            case BPF_PROG_TYPE_CGROUP_SOCK:
                return true;
        }
        return false;
    }

    // 빌드 결과물인 .o 파일을 로드한다.
    shared_ptr<bpf_object> load_bpf_object(const string& obj_path){
        if(!is_exists_file(fs::path(obj_path))){
            utils::log("pinned prog object file load failed: " + obj_path + " is not exists");
            return nullptr;
        }

        bpf_object* obj = bpf_object__open_file(obj_path.c_str(), nullptr);
        if(!obj){
            error_code ec(errno, std::generic_category());
            utils::log("bpf_object__open_file error: " + ec.message());
            return nullptr;
        }
        return shared_ptr<bpf_object>{obj, &::bpf_object__close};
    }
    // 프로그램 타입 지정. SEC("classifier"), SEC("tc") 등이 아닌 커스텀 방식은 자동 추론이 안된다.
    bpf_program* set_bpf_prog_type(shared_ptr<bpf_object> obj_ptr, const string& function_name, int type){
        if(!is_correct_bpf_prog_type(type)){
            utils::log("The bpf program type " + to_string(type) + " is not correct");
            return nullptr;
        }

        bpf_program* prog = bpf_object__find_program_by_name(obj_ptr.get(), function_name.c_str());
        if(!prog){
            error_code ec(ENOENT, std::generic_category());
            utils::log("bpf_object__find_program_by_name: " + ec.message());
            return nullptr;
        }

        bpf_program__set_type(prog, static_cast<bpf_prog_type>(type));
        return prog;
    }
    // bpf 프로그램이 사용하는 맵과 C++에서 랩퍼로 연 bpf 맵을 묶는다.
    BpfProgLoaderError reuse_bpf_map_in_prog(shared_ptr<bpf_object> obj_ptr, const vector<BpfBase*>& pinned_maps){
        for(auto pinned_map: pinned_maps){
            // bpf 프로그램의 빌드 파일(.o 파일)에서 bpf map의 정보를 가져온다.
            bpf_map* map = bpf_object__find_map_by_name(obj_ptr.get(), pinned_map->get_name().c_str());
            if(!map){
                error_code ec1(ENOENT, std::generic_category());
                utils::log("bpf_object__find_map_by_name(map name: " + pinned_map->get_name() + "): " + ec1.message());
                return BpfProgLoaderError::kProgDontUseTheBpfMapError;
            }

            // 실제로 reuse할 맵이 pinned 되어있는지 확인한다.
            fs::path pinned_map_path = pinned_map->get_pin_path();
            if(!is_exists_file(pinned_map_path)){
                utils::log(pinned_map_path.string() + " is not exists");
                return BpfProgLoaderError::kInvalidBpfMapPinPathError;
            }

            // 모든 조건을 충족하면 bpf 프로그램의 bpf map과 사용자의 wrapper를 연결한다.
            const int rc = bpf_map__reuse_fd(map, pinned_map->get_fd());
            if(rc < 0){ // 핀 경로 설정 실패
                error_code ec2(-rc, std::generic_category());
                utils::log("bpf_map__reuse_fd(map name: " + pinned_map->get_name() + "): " + ec2.message());
                return BpfProgLoaderError::kBpfProgFailedPinnedMapLoad;
            }
        }
        return BpfProgLoaderError::kNoError;
    }
    // bpf 프로그램을 커널로 업로드한다. (실제 verifier 점검이 여기서 이루어진다.)
    BpfProgLoaderError upload_bpf_program_to_kernel(shared_ptr<bpf_object> obj_ptr){
        // 업로드 — 이 시점에 맵 재사용·검증·프로그램 검증이 모두 일어난다
        int rc = bpf_object__load(obj_ptr.get());
        if(rc < 0){
            error_code ec5(-rc, std::generic_category());
            utils::log("bpf_object__load error: " + ec5.message());
            return BpfProgLoaderError::kUploadProgToKernelError;
        }
        return BpfProgLoaderError::kNoError;
    }
    // 업로드된 bpf 프로그램을 pin한다.
    pair<string, bool> pin_prog(bpf_program* prog, const string& function_name, const string& pin_dir){
        // 현재 핀이 되어있는지 확인한다.
        fs::path pinned_prog_path = fs::path(pin_dir) / fs::path(function_name);
        if(is_exists_file(pinned_prog_path)){
            utils::log("already exists the pin file: " + pinned_prog_path.string());
            return {pinned_prog_path.string(), false};
        }

        if(!make_directory_if_not_exist(fs::path(pin_dir)))
            return {"", false};

        int rc = bpf_program__pin(prog, pinned_prog_path.c_str());
        if(rc < 0){
            error_code ec(-rc, std::generic_category());
            utils::log("bpf_program__pin: " + ec.message());
            return {"", false};
        }
        return {pinned_prog_path.string(), true};
    }

    int get_bpf_prog_fd(bpf_program* prog){
        if(!prog) return -1;

        int fd = bpf_program__fd(prog);
        if(fd < 0) return -1;

        fd = ::dup(fd);
        return fd;
    }
    std::uint32_t get_bpf_prog_id(int prog_fd){
        if(prog_fd < 0){
            utils::log("get_bpf_prog_id failed: prog_fd is not invalid");
            return 0;
        }

        bpf_prog_info info = {};
        std::uint32_t info_len = sizeof(info);

        int rc = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
        if(rc < 0){
            error_code ec(-rc, std::generic_category());
            utils::log("bpf_obj_get_info_by_fd failed: " + ec.message());
            return 0;
        }
        return info.id;
    }
}

BpfProgLoader::BpfProgramPtrAndError BpfProgLoader::load_program(
    const string& prog_obj_path, const string& function_name, const vector<BpfBase*>& pinned_maps, const string& pin_dir, int type)
{
    auto obj_ptr = load_bpf_object(prog_obj_path);
    if(!obj_ptr)
        return {nullptr, BpfProgLoaderError::kLoadProgObjectError};

    bpf_program* prog = set_bpf_prog_type(obj_ptr, function_name, type);
    if(!prog)
        return  {nullptr, BpfProgLoaderError::kSetProgTypeError};

    BpfProgLoaderError reuse_map_error = reuse_bpf_map_in_prog(obj_ptr, pinned_maps);
    if(reuse_map_error != BpfProgLoaderError::kNoError)
        return {nullptr, reuse_map_error};

    BpfProgLoaderError upload_program_error = upload_bpf_program_to_kernel(obj_ptr);
    if(upload_program_error != BpfProgLoaderError::kNoError)
        return {nullptr, upload_program_error};

    auto [pinned_path, is_owner] = pin_prog(prog, function_name, pin_dir);
    if(pinned_path.empty())
        return {nullptr, BpfProgLoaderError::kProgPinError};
    
    int prog_fd = get_bpf_prog_fd(prog);
    if(prog_fd < 0)
        return {nullptr, BpfProgLoaderError::kGetProgFdError};

    std::uint32_t prog_id = get_bpf_prog_id(prog_fd);
    if(prog_id == 0)
        return {nullptr, BpfProgLoaderError::kGetProgIdError};

    BpfProgramPtr program_handle = make_shared<BpfProgram>();
    program_handle->fd = prog_fd;
    program_handle->function_name = function_name;
    program_handle->is_pin_owner = is_owner;
    program_handle->pinned_path = pinned_path;
    program_handle->prog_id = prog_id;
    program_handle->type = type;
    program_handle->section_name = bpf_program__section_name(prog);
    return {program_handle, BpfProgLoaderError::kNoError};
}