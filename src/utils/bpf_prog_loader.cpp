/*
Class Name   : bpf_prog_loader.cpp
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-09, 프로그램 작성
*/

#include "utils/bpf_prog_loader.h"
#include "utils/logger.hpp"

#include <system_error>
#include <filesystem>
#include <memory>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <errno.h>

using namespace std;
using namespace utils;

namespace fs = std::filesystem;

namespace{
    inline constexpr string_view kDefaultBpfPath = "/sys/fs/bpf/";

    bool is_exists_file(const fs::path& file_path) noexcept {
        error_code err_code;
        if(fs::exists(file_path, err_code))
            return true;
        
        if(err_code)
            utils::log("file exists check error: " + err_code.message());

        return false;
    }

    BpfProgLoaderError load_and_pin_prog_obj(const string& prog_obj_path, const string& function_name, const vector<string>& pinned_map_names){
        fs::path obj_path{prog_obj_path};
        if(!is_exists_file(obj_path))
            return BpfProgLoaderError::kProgObjectNotExistsError;

        // .o파일 열기.
        bpf_object* obj = bpf_object__open_file(obj_path.c_str(), nullptr);
        if(!obj){
            error_code ec1(errno, std::generic_category);
            utils::log("bpf_object__open_file error: " + ec1.message());
            return BpfProgLoaderError::kBpfObjectOpenFailed;
        }
        unique_ptr<bpf_object, decltype(&::bpf_object__close)> obj_ptr{obj, &::bpf_object__close};

        // 프로그램 타입 지정. SEC("classifier") 는 자동 추론이 안 된다.
        bpf_program* prog = bpf_object__find_program_by_name(obj_ptr.get(), function_name.c_str());
        if(!prog){
            error_code ec2(ENOENT, std::generic_category);
            utils::log("bpf_object__find_program_by_name: " + ec2.message());
            return BpfProgLoaderError::kBpfFunctionNameNotFoundError;
        }
        bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS); // 실제 타입 지정 파트(분류)

        // 만둘어둔 pinned map들을 붙여주는 경로.
        for(const auto& map_name: pinned_map_names){
            bpf_map* map = bpf_object__find_map_by_name(obj_ptr.get(), map_name.c_str());
            if(!map){   //실제 .o에서 해당 맵의 정의가 없음
                error_code e3(ENOENT, std::generic_category);
                utils::log("bpf_object__find_map_by_name(map name: " + map_name + "): " + ec3.message());
                return BpfProgLoaderError::kBpfProgDontUseTheMap;
            }

            // 이름으로 참조하는 맵이 실제로 어디에 핀되어있는지 알려주는 코드
            fs::path pinned_map_path = fs::path(kDefaultBpfPath)/fs::path(map_name);
            if(!is_exists_file(pinned_map_path)){
                utils::log(pinned_map_path.string() + " is not exists");
                return BpfProgLoaderError::kBpfNotExistsThePinnedMap;
            }
            const int rc = bpf_map__set_pin_path(map, pinned_map_path.c_str());
            if(rc < 0){ // 핀 경로 설정 실패
                error_code e4(-rc, std::generic_category);
                utils::log("bpf_map__set_pin_path(map name: " + map_name + "): " + ec4.message());
                return BpfProgLoaderError::kBpfProgFailedPinnedMapLoad;
            }
        }

        // 로드 — 이 시점에 맵 재사용·검증·프로그램 검증이 모두 일어난다
        int rc = bpf_object__load(obj_ptr.get());
        if(rc < 0){
            error_code e5(-rc, std::generic_category);
            utils::log("bpf_object__load error: " + ec5.message());
            return BpfProgLoaderError::kVerifierError;
        }

        // 프로그램 핀
        fs::path pinned_prog_path = fs::path(kDefaultBpfPath) / fs::path(function_name);
        if(is_exists_file(pinned_prog_path)){
            utils::log("already exists the pin file: " + pinned_prog_path.string());
            return BpfProgLoaderError::kAlreadyExistsError;
        }
        rc = bpf_program__pin(prog, pinned_prog_path.c_str());
        if(rc < 0){
            error_code e6(-rc, std::generic_category);
            utils::log("bpf_program__pin: " + ec6.message());
            return BpfProgLoaderError::kBpfProgPinError;
        }

        return BpfProgLoaderError::kNoError;
    }

    BpfProgLoaderError attach_tc_filter(int ifindex, const std::string& path, int priority, bool is_ingress = true){
        struct bpf_tc_hook hook = {};
        hook.sz           = sizeof(hook);
        hook.ifindex      = ifindex;
        hook.attach_point = is_ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;

        int rc = bpf_tc_hook_create(&hook);
        if (rc && rc != -EEXIST){
            error_code ec1(-rc, std::generic_category);
            utils::log("bpf_tc_hook_create error: " + ec1.message());
            return BpfProgLoaderError::kQdiscFailedError;
        }

        int prog_fd = bpf_obj_get(path.c_str());
        if(prog_fd < 0){
            utils::log("bpf_obj_get error: " + path.string());
            return BpfProgLoaderError::kProgGetFdError;
        }

        struct bpf_tc_opts opts = {};
        opts.sz       = sizeof(opts);
        opts.prog_fd  = prog_fd;
        opts.handle   = 1;
        opts.priority = priority;
        opts.flags    = BPF_TC_F_REPLACE;
        rc = bpf_tc_attach(&hook, &opts);

        if(rc){
            ::close(prog_fd);
            error_code ec2(-rc, std::generic_category);
            utils::log("bpf_tc_attach error: " + ec2.message());
            return BpfProgLoaderError::kBpfAttachError;
        }

        ::close(prog_fd);
        return BpfProgLoaderError::kNoError;
    }
}

BpfProgLoader::BpfProgLoader(const string& prog_path): prog_obj_path_{prog_path} {}
BpfProgLoader::~BpfProgLoader(){}

BpfProgLoaderError BpfProgLoader::load_prog(const string& function_name, const vector<string>& pinned_map_names){
    // 프로그램이 핀이 안되어있다면 핀하기
    pinned_prog_path_ = (fs::path(kDefaultBpfPath) / fs::path(function_name)).string();
    if(!is_exists_file(fs::path(pinned_prog_path_))){
        auto err = load_and_pin_prog_obj(prog_obj_path_, function_name, pinned_map_names);
        if(err != BpfProgLoaderError::kNoError)
            return err;
    }

    auto interface_snapshots = loader.snapshot();
    for(const auto& [k, v]: *interface_snapshots){
        utils::log("attach target: " + k + " <- " + pinned_prog_path_);
        if(attach_tc_filter(v.ifindex, pinned_prog_path_, 100) != BpfProgLoaderError::kNoError)
            utils::log("Success");
    }

    loader.start_monitor([this](SnapshotPtr snaps){
        for(const auto& [k, v]: *snaps){
            utils::log("attach target: " + k + " <- " + pinned_prog_path_);
            if(attach_tc_filter(v.ifindex, pinned_prog_path_, 100) != BpfProgLoaderError::kNoError)
                utils::log("Success");
        }
    });
    return BpfProgLoaderError::kNoError;
}