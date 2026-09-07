/*
Class Name   : bpf_perf_buffer_control.cpp
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-07, 프로그램 작성
*/

#include "bpf_perf_buffer_control.h"

using namespace bpf_control;
using namespace std;
namespace fs = std::filesystem;

BpfPerfBufferControl::BpfPerfBufferControl(const string& name, int page_count, void* ctx)
    : BpfBase(name, ""), page_count_(page_count), perf_buf_ctx_(ctx) {}

BpfControlErrorCode BpfPerfBufferControl::open(bool is_pinned, const string& pin_path){
    if(is_open())
        return BpfControlErrorCode::kAlreadyOpenedError; // Map is already open

    if(is_pinned){
        if(!fs::exists(pin_path))
            return BpfControlErrorCode::kNotPinnedError; // Map is not pinned

        fd_ = bpf_obj_get(pin_path.c_str()); // Open the pinned BPF map
        if(fd_ < 0)
            return BpfControlErrorCode::kOpenError; // Failed to open the pinned map

        this->pin_path_ = pin_path; // Store the pin path
    }
    else{
        const long cpu_count = ::sysconf(_SC_NPROCESSORS_ONLN);
        if(cpu_count <= 0)
            return BpfControlErrorCode::kPerfFailedToGetCpuCountError; // Failed to get the number of CPUs
        
        if(page_count_ <= 0 || (page_count_ & (page_count_ - 1)) != 0) // Check if page_count is a power of 2
            return BpfControlErrorCode::kInvalidPerfPageSizeError; // Invalid page count for perf buffer. It must be a 2^n value

        LIBBPF_OPTS(bpf_map_create_opts, opts);
        fd_ = bpf_map_create(BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                            name_.c_str(),
                            sizeof(uint32_t),
                            sizeof(uint32_t),
                            static_cast<uint32_t>(cpu_count),
                            &opts);
        if(fd_ < 0)
            return BpfControlErrorCode::kNotOpenedError; // Failed to create the perf buffer map
    }

    return BpfControlErrorCode::kNoError;
}

BpfControlErrorCode BpfPerfBufferControl::event_buffer_create(){
    if(!is_open())
        return BpfControlErrorCode::kNotOpenedError; // Perf buffer is not open

    // sample_cb_는 커널에서 이벤트가 발생했을 때 호출되는 콜백함수이고, lost_cb_는 이벤트를 놓쳤을 때 호출되는 콜백함수임.
    if(!sample_cb_ || !lost_cb_){
        close(); // Close the map if callbacks are not set
        return BpfControlErrorCode::kCallbackNotSetError; // Callbacks must be set before opening the perf buffer
    }

    // perf_buffer는 RAII로 관리되며, perf_buffer__free를 사용하여 자동으로 해제됨.
    perfbuf_.reset(perf_buffer__new(fd_, page_count_, sample_cb_, lost_cb_, perf_buf_ctx_, nullptr));
    if(!perfbuf_){
        close(); // Close the map if perf buffer creation fails
        return BpfControlErrorCode::kBufferMakeError; // Failed to create the perf buffer
    }

    return BpfControlErrorCode::kNoError;
}

// timeout_ms는 perf buffer를 poll할 때의 타임아웃 시간(밀리초 단위)이며, -1이면 무한 대기함. (즉, blocking됨)
BpfControlErrorCode BpfPerfBufferControl::poll(int timeout_ms){
    if(!is_open())
        return BpfControlErrorCode::kNotOpenedError; // Perf buffer is not open
    
    if(!perfbuf_)
        return BpfControlErrorCode::kBufferMakeError; // Perf buffer is not created

    int ret = perf_buffer__poll(perfbuf_.get(), timeout_ms);
    if(ret < 0 && ret != -EINTR)
        return BpfControlErrorCode::kPollingError; // Failed to poll the perf buffer

    return BpfControlErrorCode::kNoError;
}

BpfControlErrorCode BpfPerfBufferControl::close(){
    perfbuf_.reset(); // Reset the perf buffer pointer
    return BpfBase::close(); // Call the base class close method
}
