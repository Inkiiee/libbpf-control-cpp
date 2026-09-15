/*
Class Name   : bpf_map_control.cpp
@version     : 1.1
@author      : Inkiiee
@modify      : 2026-09-07, 프로그램 작성
               2026-09-14, pin되어있는 맵을 사용할 때, 정보를 가져오는 load_map_info 함수 추가
*/

#include "bpf_map_control.h"

#include <cerrno>
#include <vector>

using namespace bpf_control;
using namespace std;
namespace fs = std::filesystem;

BpfMapControl::BpfMapControl(const string& name, size_t key_sz, size_t value_sz, size_t max_ent, bpf_map_type map_type)
    : BpfBase(name, ""), key_size_(key_sz), value_size_(value_sz), max_entries_(max_ent), map_type_(map_type){}

BpfControlErrorCode BpfMapControl::open(bool is_pinned, const string& pin_path){
    if(is_open())
        return BpfControlErrorCode::kAlreadyOpenedError; // Map is already open

    if(is_pinned){
        error_code ignored_ec;
        if(!fs::exists(pin_path, ignored_ec)){
            fd_ = -1; // Reset fd_ to indicate failure
            return BpfControlErrorCode::kNotOpenedError; // Map is not pinned
        }

        fd_ = bpf_obj_get(pin_path.c_str()); // Open the pinned BPF map
        if(fd_ < 0){
            fd_ = -1; // Reset fd_ to indicate failure
            return BpfControlErrorCode::kOpenError; // Failed to open the pinned map
        }

        if(!load_map_info()){
            close();
            return BpfControlErrorCode::kOpenError;
        }
        
        this->pin_path_ = pin_path; // Store the pin path
        return BpfControlErrorCode::kNoError;
    }

    // LIBBPF_OPTS는 필수는 아니지만 사용하는 것이 좋음. (표준이며, 옵션 구조체를 초기화하는데 사용됨)
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    fd_ = bpf_map_create(map_type_,
                        name_.c_str(),
                        static_cast<uint32_t>(key_size_),
                        static_cast<uint32_t>(value_size_),
                        static_cast<uint32_t>(max_entries_),
                        &opts); // Create a new BPF map
    if(fd_ < 0){
        fd_ = -1; // Reset fd_ to indicate failure
        return BpfControlErrorCode::kOpenError; // Failed to create the map
    }

    return BpfControlErrorCode::kNoError;
}

BpfControlErrorCode BpfMapControl::update(const void* key, const void* value, std::uint64_t flags){
    if(!is_open())
        return BpfControlErrorCode::kNotOpenedError; // Map is not open

    if(bpf_map_update_elem(fd_, key, value, flags) < 0)
        return BpfControlErrorCode::kUpdateError; // Failed to update the map

    return BpfControlErrorCode::kNoError;
}

BpfControlErrorCode BpfMapControl::lookup(const void* key, void* value){
    if(!is_open())
        return BpfControlErrorCode::kNotOpenedError; // Map is not open

    if(bpf_map_lookup_elem(fd_, key, value) < 0)
        return BpfControlErrorCode::kLookupError; // Failed to lookup the map

    return BpfControlErrorCode::kNoError;
}

BpfControlErrorCode BpfMapControl::delete_entry(const void* key){
    if(!is_open())
        return BpfControlErrorCode::kNotOpenedError; // Map is not open

    if(bpf_map_delete_elem(fd_, key) < 0)
        return BpfControlErrorCode::kDeleteError; // Failed to delete the map entry

    return BpfControlErrorCode::kNoError;
}

BpfControlErrorCode BpfMapControl::clear(){
    if(!is_open())
        return BpfControlErrorCode::kNotOpenedError; // Map is not open

    vector<uint8_t> key(key_size_);

    while (true) { // 첫번째 키의 값을 지우고, 다시 첫번째 키를 가져와 지우는 것을 반복함. (즉, 하나씩 순회하며 지움)
        auto err = get_next_key(nullptr, key.data());
        if(err == BpfControlErrorCode::kGetNextKeyNotFoundError)
            return BpfControlErrorCode::kNoError;

        if(err != BpfControlErrorCode::kNoError)
            return err; // Failed to get the next key

        err = delete_entry(key.data());
        if(err != BpfControlErrorCode::kNoError)
            return err; // Failed to delete the map entry
    }
}

BpfControlErrorCode BpfMapControl::get_next_key(const void* key, void* next_key){
    if(!is_open())
        return BpfControlErrorCode::kNotOpenedError; // Map is not open

    if(next_key == nullptr)
        return BpfControlErrorCode::kGetNextKeyInvalidError; // Next key pointer is null

    if(bpf_map_get_next_key(fd_, key, next_key) < 0){
        if(errno == ENOENT)
            return BpfControlErrorCode::kGetNextKeyNotFoundError; // No more keys
        else
            return BpfControlErrorCode::kGetNextKeyError; // Failed to get the next key
    }

    return BpfControlErrorCode::kNoError;
}

bool BpfMapControl::load_map_info(){
    if(!is_open()) return false;

    bpf_map_info info{};
    std::uint32_t info_len = sizeof(info);
    int rc = bpf_obj_get_info_by_fd(fd_, &info, &info_len);
    if(rc < 0) return false;

    if(info.type == BPF_MAP_TYPE_PERF_EVENT_ARRAY
    || info.type == BPF_MAP_TYPE_RINGBUF) return false;

    name_ = info.name;
    key_size_ = info.key_size;
    value_size_ = info.value_size;
    map_type_ = static_cast<bpf_map_type>(info.type);
    max_entries_ = info.max_entries;
    return true;
}
