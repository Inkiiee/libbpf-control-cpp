#ifndef BPF_RUNTIME_HPP
#define BPF_RUNTIME_HPP

#include <bpf/libbpf.h>

namespace bpf_runtime{
    // 해당 함수는 0.7 버전~ 1.0이전까지의 libbpf와 1.0 이후부터의 호환성을 위하여 존재한다.
    // libbpf 기능을 사용할거면 반드시 그전에 선 호출되야한다.
    // 실제 초기화는 최초 1회만 수행된다(함수 지역 static 초기화라 스레드 안전).
    //
    // RLIMIT_MEMLOCK 은 직접 건드리지 않는다. LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK 이
    // 켜지면 libbpf 가 커널의 memcg 기반 BPF 메모리 회계 지원 여부를 보고,
    // 지원하지 않는 구형 커널에서만 알아서 bump 한다.
    // 한도를 직접 정해야 하면 libbpf_set_memlock_rlim() 을 쓰되,
    // 최초 bpf_map_create()/bpf_prog_load()/bpf_object__load() 보다 먼저 호출해야 한다.
    inline int initialize() noexcept {
        static const int result = libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

        return result;
    }
}

#endif
