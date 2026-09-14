/*
Class Name   : bpf_prog_loader.cpp
@version     : 1.3
@author      : Inkiiee
@modify      : 2026-09-09, 프로그램 작성
               2026-09-14, pin한 파일에 대한 소유권 명시 및 set_pin_path를 bpf_reuse_fd로 수정
               2026-09-14, 필터 부착 인터페이스 필터 추가 및 자동 재시도 기능 추가
*/

#include "utils/bpf_prog_loader.h"
#include "utils/logger.hpp"
#include "bpf_control_base.hpp"

#include <system_error>
#include <filesystem>
#include <memory>
#include <chrono>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <errno.h>

using namespace std;
using namespace utils;
using namespace nic_check;
using namespace bpf_control;
using namespace chrono_literals;

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

    int get_prog_id(const std::string& pin_path){
        int fd = bpf_obj_get(pin_path.c_str());
        if(fd < 0) return -1;

        bpf_prog_info info = {};
        std::uint32_t info_len = sizeof(info);

        int rc = bpf_obj_get_info_by_fd(fd, &info, &info_len);
        if(rc < 0){
            ::close(fd);
            return -1;
        }

        ::close(fd);
        return info.id;
    }
}

BpfProgLoader::BpfProgLoader(const string& prog_path, int handle, int priority, bool is_ingress): 
    prog_obj_path_{prog_path}, handle_{handle}, priority_{priority}, prog_id_{-1}, is_ingress_{is_ingress}, is_owner_of_the_pin_{false} {}
BpfProgLoader::~BpfProgLoader(){
    loader.stop_monitor();

    if(attach_recovery_thread_.joinable()){
        attach_recovery_thread_.request_stop();
        has_failed_filter_.store(true);
        has_failed_filter_.notify_all();
        attach_recovery_thread_.join();
    }

    auto snaps = loader.snapshot();
    for(const auto& [k, v] : *snaps){
        {
            lock_guard<mutex> lock(target_nics_mutex_);
            if(!target_nics_.empty() && target_nics_.find(k) == target_nics_.end()) continue;
        }
        auto is_applied = is_applied_filter_by_ifname(k);
        if(is_applied && *is_applied){
            BpfProgLoaderError detach_err = detach_filter_by_ifname(k);
            if(detach_err != BpfProgLoaderError::kNoError)
                utils::log(pinned_prog_path_ + " detach failed from " + k);
        }
    }
    if(!pinned_prog_path_.empty() && is_owner_of_the_pin_){
        error_code ignore_ec;
        fs::remove(pinned_prog_path_, ignore_ec);
    }
}

BpfProgLoaderError BpfProgLoader::load_prog(const string& function_name, const vector<BpfBase*>& pinned_maps){
    // 프로그램이 핀이 안되어있다면 핀하기
    pinned_prog_path_ = (fs::path(kDefaultBpfPath) / fs::path(function_name)).string();
    if(!is_exists_file(fs::path(pinned_prog_path_))){
        auto err = load_and_pin_prog_obj(function_name, pinned_maps);
        if(err != BpfProgLoaderError::kNoError)
            return err;
    }

    // prog id 얻기
    prog_id_ = get_prog_id(pinned_prog_path_);
    if(prog_id_ < 0){
        utils::log("Failed get prog id (pinned path: " + pinned_prog_path_ + ")");
        return BpfProgLoaderError::kGetProgIdError;
    }

    if(attach_recovery_thread_.joinable()){
        attach_recovery_thread_.request_stop();
        has_failed_filter_.store(true);
        has_failed_filter_.notify_all();
        attach_recovery_thread_.join();
    }
    has_failed_filter_.store(false);
    attach_recovery_thread_ = jthread([this](std::stop_token stop){
        while(!stop.stop_requested()){
            has_failed_filter_.wait(false);
            if(stop.stop_requested()) break;

            bool is_success = false;
            {
                lock_guard<mutex> lock(failed_nics_mutex_);

                unordered_set<string> pending_nics;
                pending_nics.swap(failed_nics_);
                for(const auto& i: pending_nics){
                    {
                        lock_guard<mutex> target_lock(target_nics_mutex_);
                        if(!target_nics_.empty() && target_nics_.find(i) == target_nics_.end()) continue;
                    }
                    utils::log("re-attach target: " + i + " <- " + pinned_prog_path_);
                    if(attach_filter_by_ifname(i) == BpfProgLoaderError::kNoError)
                        utils::log("Success");
                    else{
                        utils::log("filter re-attach failed (interface name: " + i + ")");
                        failed_nics_.insert(i);
                        has_failed_filter_.store(true);
                        has_failed_filter_.notify_one();
                    }
                }

                if(failed_nics_.empty()){
                    is_success = true;
                    has_failed_filter_.store(false);
                }
            }

            if(!is_success)
                this_thread::sleep_for(1000ms);
        }
    });

    auto interface_snapshots = loader.snapshot();
    attach_filters(interface_snapshots);

    bool is_start = loader.start_monitor([this](InterfaceLoader::SnapshotPtr snaps){
        attach_filters(snaps);
    });

    if(is_start)
        return BpfProgLoaderError::kNoError;

    return BpfProgLoaderError::kInterfaceMonitorFailed;
}

BpfProgLoaderError BpfProgLoader::load_and_pin_prog_obj(const string& function_name, const vector<BpfBase*>& pinned_maps){
    fs::path obj_path{prog_obj_path_};
    if(!is_exists_file(obj_path))
        return BpfProgLoaderError::kProgObjectNotExistsError;

    // .o파일 열기.
    bpf_object* obj = bpf_object__open_file(obj_path.c_str(), nullptr);
    if(!obj){
        error_code ec1(errno, std::generic_category());
        utils::log("bpf_object__open_file error: " + ec1.message());
        return BpfProgLoaderError::kBpfObjectOpenFailed;
    }
    unique_ptr<bpf_object, decltype(&::bpf_object__close)> obj_ptr{obj, &::bpf_object__close};

    // 프로그램 타입 지정. SEC("classifier") 는 자동 추론이 안 된다.
    bpf_program* prog = bpf_object__find_program_by_name(obj_ptr.get(), function_name.c_str());
    if(!prog){
        error_code ec2(ENOENT, std::generic_category());
        utils::log("bpf_object__find_program_by_name: " + ec2.message());
        return BpfProgLoaderError::kBpfFunctionNameNotFoundError;
    }
    bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS); // 실제 타입 지정 파트(분류)

    // 만둘어둔 pinned map들을 붙여주는 경로.
    for(auto pinned_map: pinned_maps){
        bpf_map* map = bpf_object__find_map_by_name(obj_ptr.get(), pinned_map->get_name().c_str());
        if(!map){   //실제 .o에서 해당 맵의 정의가 없음
            error_code ec3(ENOENT, std::generic_category());
            utils::log("bpf_object__find_map_by_name(map name: " + pinned_map->get_name() + "): " + ec3.message());
            return BpfProgLoaderError::kBpfProgDontUseTheMap;
        }

        // 이름으로 참조하는 맵이 실제로 어디에 핀되어있는지 알려주는 코드
        fs::path pinned_map_path = pinned_map->get_pin_path();
        if(!is_exists_file(pinned_map_path)){
            utils::log(pinned_map_path.string() + " is not exists");
            return BpfProgLoaderError::kBpfNotExistsThePinnedMap;
        }
        const int rc = bpf_map__reuse_fd(map, pinned_map->get_fd());
        if(rc < 0){ // 핀 경로 설정 실패
            error_code ec4(-rc, std::generic_category());
            utils::log("bpf_map__reuse_fd(map name: " + pinned_map->get_name() + "): " + ec4.message());
            return BpfProgLoaderError::kBpfProgFailedPinnedMapLoad;
        }
    }

    // 로드 — 이 시점에 맵 재사용·검증·프로그램 검증이 모두 일어난다
    int rc = bpf_object__load(obj_ptr.get());
    if(rc < 0){
        error_code ec5(-rc, std::generic_category());
        utils::log("bpf_object__load error: " + ec5.message());
        return BpfProgLoaderError::kVerifierError;
    }

    // 프로그램 핀
    fs::path pinned_prog_path = fs::path(kDefaultBpfPath) / fs::path(function_name);
    if(is_exists_file(pinned_prog_path)){
        utils::log("already exists the pin file: " + pinned_prog_path.string());
        is_owner_of_the_pin_ = false;
        return BpfProgLoaderError::kNoError; // 다른 곳에서 핀이 되어있어도 NoError이다.
    }
    rc = bpf_program__pin(prog, pinned_prog_path.c_str());
    if(rc < 0){
        error_code ec6(-rc, std::generic_category());
        utils::log("bpf_program__pin: " + ec6.message());
        return BpfProgLoaderError::kBpfProgPinError;
    }

    is_owner_of_the_pin_ = true;
    return BpfProgLoaderError::kNoError;
}

optional<bool> BpfProgLoader::is_applied_filter(int ifindex){
    struct bpf_tc_hook hook = {};
    hook.sz           = sizeof(hook);
    hook.ifindex      = ifindex;
    hook.attach_point = is_ingress_ ? BPF_TC_INGRESS : BPF_TC_EGRESS;

    struct bpf_tc_opts query = {};
    query.sz = sizeof(query);
    query.handle = handle_;
    query.priority = priority_;
    query.prog_id = prog_id_;

    int rc = bpf_tc_query(&hook, &query);
    if(rc == 0 && query.prog_id == prog_id_) return true;
    else if(rc == -ENOENT) return false;
    return nullopt;
}

std::optional<bool> BpfProgLoader::is_applied_filter_by_ifname(const std::string& ifname){
    auto ifindex = loader.get_ifindex_by_ifname(ifname);
    return is_applied_filter(ifindex);
}

void BpfProgLoader::attach_filters(InterfaceLoader::SnapshotPtr snaps){
    for(const auto& [k, v]: *snaps){
        {
            lock_guard<mutex> lock(target_nics_mutex_);
            if(!target_nics_.empty() && target_nics_.find(k) == target_nics_.end()) continue;
        }

        utils::log("attach target: " + k + " <- " + pinned_prog_path_);
        if(attach_filter_by_ifname(k) == BpfProgLoaderError::kNoError)
            utils::log("Success");
        else{
            utils::log("filter attach failed (interface name: " + k + ")");
            lock_guard<mutex> failed_nics_lock(failed_nics_mutex_);
            failed_nics_.insert(k);
            has_failed_filter_.store(true);
            has_failed_filter_.notify_one();
        }
    }
}

BpfProgLoaderError BpfProgLoader::attach_filter(int ifindex){
    optional<bool> is_exist_filter = is_applied_filter(ifindex);
    if(is_exist_filter && *is_exist_filter)
        return BpfProgLoaderError::kNoError;

    struct bpf_tc_hook hook = {};
    hook.sz           = sizeof(hook);
    hook.ifindex      = ifindex;
    hook.attach_point = is_ingress_ ? BPF_TC_INGRESS : BPF_TC_EGRESS;

    int rc = bpf_tc_hook_create(&hook);
    if (rc && rc != -EEXIST){
        error_code ec1(-rc, std::generic_category());
        utils::log("bpf_tc_hook_create error: " + ec1.message());
        return BpfProgLoaderError::kQdiscFailedError;
    }

    int prog_fd = bpf_obj_get(pinned_prog_path_.c_str());
    if(prog_fd < 0){
        utils::log("bpf_obj_get error: " + pinned_prog_path_);
        return BpfProgLoaderError::kProgGetFdError;
    }

    struct bpf_tc_opts opts = {};
    opts.sz       = sizeof(opts);
    opts.prog_fd  = prog_fd;
    opts.handle   = handle_;
    opts.priority = priority_;
    opts.flags    = BPF_TC_F_REPLACE;
    rc = bpf_tc_attach(&hook, &opts);

    if(rc){
        ::close(prog_fd);
        error_code ec2(-rc, std::generic_category());
        utils::log("bpf_tc_attach error: " + ec2.message());
        return BpfProgLoaderError::kBpfAttachError;
    }

    ::close(prog_fd);
    return BpfProgLoaderError::kNoError;
}

BpfProgLoaderError BpfProgLoader::attach_filter_by_ifname(const string& ifname){
    auto ifindex = loader.get_ifindex_by_ifname(ifname);
    return attach_filter(ifindex);
}

BpfProgLoaderError BpfProgLoader::detach_filter(int ifindex){
    struct bpf_tc_hook hook = {};
    hook.sz           = sizeof(hook);
    hook.ifindex      = ifindex;
    hook.attach_point = is_ingress_ ? BPF_TC_INGRESS : BPF_TC_EGRESS;

    struct bpf_tc_opts opts = {};
    opts.sz       = sizeof(opts);
    opts.handle   = handle_;
    opts.priority = priority_;
    // prog_fd / prog_id / flags 는 0 이어야 한다

    int rc = bpf_tc_detach(&hook, &opts);
    if(rc == 0 || rc == -ENOENT)     // 없으면 이미 목적 달성
        return BpfProgLoaderError::kNoError;

    error_code ec(-rc, std::generic_category());
    utils::log("bpf_tc_detach error: " + ec.message());
    return BpfProgLoaderError::kBpfDetachError;
}

BpfProgLoaderError BpfProgLoader::detach_filter_by_ifname(const std::string& ifname){
    auto ifindex = loader.get_ifindex_by_ifname(ifname);
    return detach_filter(ifindex);
}

void BpfProgLoader::add_target_nic(const string& target_ifname){
    lock_guard<mutex> lock(target_nics_mutex_);
    if(target_nics_.find(target_ifname) != target_nics_.end()) return;

    target_nics_.insert(target_ifname);
    auto is_applied = is_applied_filter_by_ifname(target_ifname);
    if((is_applied && (*is_applied == false)) && prog_id_ >= 0){
        auto err = attach_filter_by_ifname(target_ifname);
        if(err == BpfProgLoaderError::kNoError)
            utils::log("attached filter in " + target_ifname);
        else
            utils::log("failed attach filter in " + target_ifname);
    }
}
void BpfProgLoader::remove_target_nic(const string& target_ifname){
    lock_guard<mutex> lock(target_nics_mutex_);
    if(target_nics_.find(target_ifname) == target_nics_.end()) return;

    auto is_applied = is_applied_filter_by_ifname(target_ifname);
    if((is_applied && *is_applied) && prog_id_ >= 0){
        auto err = detach_filter_by_ifname(target_ifname);
        if(err == BpfProgLoaderError::kNoError)
            utils::log("removed filter in " + target_ifname);
        else
            utils::log("failed remove filter in " + target_ifname);
    }

    target_nics_.erase(target_ifname);
}
void BpfProgLoader::clear_target_nics(){
    lock_guard<mutex> lock(target_nics_mutex_);
    for(const auto& i: target_nics_){
        auto is_applied = is_applied_filter_by_ifname(i);
        if((is_applied && *is_applied) && prog_id_ >= 0){
            auto err = detach_filter_by_ifname(i);
            if(err == BpfProgLoaderError::kNoError)
                utils::log("removed filter in " + i);
            else
                utils::log("failed remove filter in " + i);
        }
    }
    target_nics_.clear();
}
vector<string> BpfProgLoader::get_all_target_nics(){
    lock_guard<mutex> lock(target_nics_mutex_);
    return vector<string>(target_nics_.begin(), target_nics_.end());
}