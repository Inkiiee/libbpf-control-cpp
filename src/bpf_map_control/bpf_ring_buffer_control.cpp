/*
Class Name   : bpf_ring_buffer_control.cpp
@version     : 1.1
@author      : Inkiiee
@modify      : 2026-09-07, 프로그램 작성
               2026-09-14, pin되어있는 맵을 사용할 때, 정보를 가져오는 load_map_info 함수 추가
*/

#include "bpf_ring_buffer_control.h"

#include "bpf_runtime/bpf_runtime.hpp"

using namespace bpf_control;
using namespace std;
namespace fs = std::filesystem;

BpfRingBufferControl::BpfRingBufferControl(const string& name, size_t buf_size, void* ctx)
    : BpfBase(name, ""), buf_size_(buf_size), ringbuf_ctx_(ctx) {}

BpfRingBufferControl::~BpfRingBufferControl() { ringbuf_.reset(); }

BpfControlErrorCode BpfRingBufferControl::open(bool is_pinned, const string& pin_path){
    if(bpf_runtime::initialize() < 0)
        return BpfControlErrorCode::kBpfRuntimeInitError;

    if(is_open())
        return BpfControlErrorCode::kAlreadyOpenedError; // Map is already open

    if(is_pinned){
        error_code ignored_ec;
        if(!fs::exists(pin_path, ignored_ec))
            return BpfControlErrorCode::kNotPinnedError; // Map is not pinned

        fd_ = bpf_obj_get(pin_path.c_str()); // Open the pinned BPF map
        if(fd_ < 0)
            return BpfControlErrorCode::kOpenError; // Failed to open the pinned map

        const BpfControlErrorCode info_error = load_map_info();
        if(info_error != BpfControlErrorCode::kNoError){
            close();
            return info_error;
        }

        this->pin_path_ = pin_path; // Store the pin path
    }
    else{
        if(buf_size_ <= 0 || (buf_size_ & (buf_size_ - 1)) != 0) // Check if buf_size is a power of 2
            return BpfControlErrorCode::kInvalidRingBufferSizeError; // Invalid buffer size for ring buffer

        LIBBPF_OPTS(bpf_map_create_opts, opts);
        fd_ = bpf_map_create(BPF_MAP_TYPE_RINGBUF,
                            name_.c_str(),
                            0,              // key_size (ringbuf은 0)
                            0,              // value_size (ringbuf은 0)
                            static_cast<uint32_t>(buf_size_),
                            &opts);
        if(fd_ < 0){
            fd_ = -1;
            return BpfControlErrorCode::kOpenError; // Failed to create the ring buffer map
        }
    }

    return BpfControlErrorCode::kNoError;
}

BpfControlErrorCode BpfRingBufferControl::event_buffer_create(){
    if(!is_open())
        return BpfControlErrorCode::kNotOpenedError; // Ring buffer map is not open

    // sample_cb_는 커널에서 이벤트가 발생했을 때 호출되는 콜백함수임.
    // ring buffer는 모든 cpu가 공유하는 링 형태의 큐를 만드는 것이라서, 이벤트 순서가 보장되고, 이벤트를 놓치지 않음.
    if(!sample_cb_){
        close(); // Close the map if callback is not set
        return BpfControlErrorCode::kCallbackNotSetError; // Callback must be set before opening the ring buffer
    }

    // RAII로 관리되며, ring_buffer__free를 사용하여 자동으로 해제됨.
    ringbuf_.reset(ring_buffer__new(fd_, sample_cb_, ringbuf_ctx_, nullptr));
    if(!ringbuf_){
        close(); // Close the map if ring buffer creation fails
        return BpfControlErrorCode::kBufferMakeError; // Failed to create the ring buffer
    }

    return BpfControlErrorCode::kNoError;
}

BpfControlErrorCode BpfRingBufferControl::poll(int timeout_ms){
    if(!is_open())
        return BpfControlErrorCode::kNotOpenedError; // Ring buffer map is not open
    
    if(!ringbuf_)
        return BpfControlErrorCode::kBufferMakeError; // Ring buffer is not created
    
    int ret = ring_buffer__poll(ringbuf_.get(), timeout_ms);
    if(ret < 0 && ret != -EINTR)
        return BpfControlErrorCode::kPollingError; // Failed to poll the ring buffer

    return BpfControlErrorCode::kNoError;
}

BpfControlErrorCode BpfRingBufferControl::close(){
    ringbuf_.reset(); // Reset the ring buffer pointer
    return BpfBase::close(); // Call the base class close method
}

// 핀에 있는 ring buffer 가 생성자로 요청한 형태와 같은지 확인한다.
// 커널 값으로 덮어쓰지 않는 이유는 BpfMapControl::load_map_info 참고.
BpfControlErrorCode BpfRingBufferControl::load_map_info(){
    if(!is_open()) return BpfControlErrorCode::kNotOpenedError;

    bpf_map_info info{};
    std::uint32_t info_len = sizeof(info);
    int rc = bpf_obj_get_info_by_fd(fd_, &info, &info_len);
    if(rc < 0) return BpfControlErrorCode::kOpenError;

    if(info.type != BPF_MAP_TYPE_RINGBUF){
        utils::log("pinned object is not a ring buffer map");
        return BpfControlErrorCode::kPinnedMapMismatchError;
    }

    // ring buffer 는 max_entries 가 바이트 단위 버퍼 크기다.
    if(buf_size_ != info.max_entries){
        utils::log("pinned ring buffer size mismatch: requested=" + to_string(buf_size_) +
                   " pinned=" + to_string(info.max_entries));
        return BpfControlErrorCode::kPinnedMapMismatchError;
    }

    name_ = info.name;
    return BpfControlErrorCode::kNoError;
}
