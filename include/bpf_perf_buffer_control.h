/*
Class Name   : bpf_perf_buffer_control.h
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-07, 프로그램 작성
*/

#ifndef BPF_PERF_BUFFER_CONTROL_H
#define BPF_PERF_BUFFER_CONTROL_H

#include <memory>

#include "bpf_control_base.hpp"

namespace bpf_control{
    class BpfPerfBufferControl: public BpfBase {  
    public:
        using perf_buffer_sample_callback = perf_buffer_sample_fn;
        using perf_buffer_lost_callback = perf_buffer_lost_fn;
        using perf_buffer_ptr = std::unique_ptr<struct perf_buffer, decltype(&perf_buffer__free)>;  

        BpfPerfBufferControl() = delete;
        BpfPerfBufferControl(const BpfPerfBufferControl&) = delete;
        BpfPerfBufferControl& operator=(const BpfPerfBufferControl&) = delete;

        BpfPerfBufferControl(BpfPerfBufferControl&&) = default;
        BpfPerfBufferControl& operator=(BpfPerfBufferControl&&) = default;
        BpfPerfBufferControl(const std::string& name, int page_count=8, void* ctx=nullptr);

        // 기본적으로 bpf map과는 open과정이 조금 다름.
        virtual BpfControlErrorCode open(bool is_pinned = false, const std::string& pin_path = "") override;
        BpfControlErrorCode event_buffer_create(); // 커널에게 받은 이벤트를 넣을 사용자 영역 버퍼 생성.
        BpfControlErrorCode poll(int timeout_ms); // 커널의 이벤트를 지속적으로 확인하고 가져오는 기능. (thread를 분리할것. 실행시 blocking됨)
        virtual BpfControlErrorCode close() override; // perf buffer를 닫고, bpf map도 닫음.

        int get_page_count() const { return page_count_; } // perf buffer의 페이지 수(기본값 8, 2^n이어야함)
        void* get_perf_buf_ctx() const { return perf_buf_ctx_; } // perf buffer의 콜백함수에서 사용할 수 있는 사용자 영역 포인터. (ex: struct pointer)
        void set_perf_buf_ctx(void* ctx) { perf_buf_ctx_ = ctx; } // perf buffer의 콜백함수에서 사용할 수 있는 사용자 영역 포인터를 설정. (ex: struct pointer)
        
        void set_callbacks(perf_buffer_sample_callback sample_cb, perf_buffer_lost_callback lost_cb){
            this->sample_cb_ = sample_cb;
            this->lost_cb_ = lost_cb;
        }
    private:
        int page_count_; // perf buffer의 페이지 수(기본값 8, 반드시 2^n이어야함)
        void * perf_buf_ctx_ = nullptr;
        perf_buffer_ptr perfbuf_ = {nullptr, &perf_buffer__free}; // perf buffer를 관리하는 unique_ptr. perf_buffer__free를 사용하여 자동으로 해제됨.
        perf_buffer_sample_callback sample_cb_ = nullptr; // 커널에서 이벤트가 발생했을 때 호출되는 콜백함수
        perf_buffer_lost_callback lost_cb_ = nullptr; // 커널에서 이벤트를 놓쳤을 때 호출되는 콜백함수
    };
}

#endif // BPF_PERF_BUFFER_CONTROL_H