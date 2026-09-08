/*
Class Name   : bpf_ring_buffer_control.h
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-07, 프로그램 작성
*/

#ifndef BPF_RING_BUFFER_CONTROL_H
#define BPF_RING_BUFFER_CONTROL_H

#include "bpf_control_base.hpp"

namespace bpf_control{
    class BpfRingBufferControl: public BpfBase {
    public:
        using ring_buffer_sample_callback = ring_buffer_sample_fn;
        using ring_buffer_ptr = std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)>;

        BpfRingBufferControl() = delete;
        BpfRingBufferControl(const BpfRingBufferControl&) = delete;
        BpfRingBufferControl& operator=(const BpfRingBufferControl&) = delete;

        BpfRingBufferControl(BpfRingBufferControl&&) = default;
        BpfRingBufferControl& operator=(BpfRingBufferControl&&) = default;
        BpfRingBufferControl(const std::string& name, std::size_t buf_size=1024*64u, void* ctx=nullptr);

        // 기본적으로 bpf map과는 open과정이 조금 다름.
        virtual BpfControlErrorCode open(bool is_pinned = false, const std::string& pin_path = "") override;
        BpfControlErrorCode event_buffer_create(); // 커널에게 받은 이벤트를 넣을 사용자 영역 버퍼 생성.
        BpfControlErrorCode poll(int timeout_ms); // 커널의 이벤트를 지속적으로 확인하고 가져오는 기능. (thread를 분리할것. 실행시 blocking됨)
        virtual BpfControlErrorCode close() override; // ring buffer를 닫고, bpf map도 닫음.

        std::size_t get_buf_size() const { return buf_size_; } // ring buffer의 버퍼 크기(기본값 64KB, 반드시 2^n이어야함)
        void* get_ringbuf_ctx() const { return ringbuf_ctx_; } // ring buffer의 콜백함수에서 사용할 수 있는 사용자 영역 포인터. (ex: struct pointer)
        void set_ringbuf_ctx(void* ctx) { ringbuf_ctx_ = ctx; } // ring buffer의 콜백함수에서 사용할 수 있는 사용자 영역 포인터를 설정. (ex: struct pointer)
        
        // ring buffer의 콜백함수 설정. sample_cb는 커널에서 이벤트가 발생했을 때 호출되는 콜백함수
        void set_callback(ring_buffer_sample_callback sample_cb){ this->sample_cb_ = sample_cb; }
    private:
        std::size_t buf_size_; // ring buffer의 버퍼 크기(기본값 64KB, 반드시 2^n이어야함)
        void * ringbuf_ctx_ = nullptr; // ring buffer의 콜백함수에서 사용할 수 있는 사용자 영역 포인터. (ex: struct pointer)
        ring_buffer_ptr ringbuf_ = {nullptr, &ring_buffer__free}; // ring buffer를 관리하는 unique_ptr. ring_buffer__free를 사용하여 자동으로 해제됨.
        ring_buffer_sample_callback sample_cb_ = nullptr; // 커널에서 이벤트가 발생했을 때 호출되는 콜백함수
        // 중요: ring buffer는 모든 cpu가 공유하는 링 형태의 큐를 만드는 것이라서, 이벤트 순서가 보장됨.
        // 추가로 모든 cpu가 공유하는 큐를 사용하기 때문에 이벤트를 놓치지 않음. (단, 큐가 꽉 차면 이벤트를 놓침)
    };
}

#endif // BPF_RING_BUFFER_CONTROL_H