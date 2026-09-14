# libbpf-control-cpp

Linux 네트워크 인터페이스의 생명주기를 감시하고, TC eBPF 프로그램과 pinned BPF map을 C++에서 관리하는 userspace control plane 예제입니다.

이 브랜치의 범위는 **NIC hotplug 대응**입니다. 시작 시 존재하는 모든 non-loopback NIC에 TC 프로그램을 attach하고, 실행 중 NIC 구성이 바뀌면 netlink 이벤트를 받아 최신 인터페이스 snapshot에 다시 적용합니다. 실행 중 attach 대상 정책을 추가·삭제하는 기능은 포함하지 않습니다.

## 핵심 구성

```text
InterfaceLoader
  └─ getifaddrs snapshot + NETLINK_ROUTE monitoring
                    │
                    ▼
BpfProgLoader
  └─ object load → pinned map reuse → program pin → TC attach/detach
                    │
                    ▼
BPF control wrappers
  └─ map / ring buffer / perf buffer FD와 pin lifecycle 관리
```

### InterfaceLoader

- `getifaddrs()`로 non-loopback NIC 정보를 snapshot으로 생성합니다.
- `NETLINK_ROUTE`의 link 및 IPv4 address 이벤트를 감시합니다.
- 짧은 시간에 연속으로 발생하는 netlink 이벤트를 debounce한 뒤 한 번만 갱신합니다.
- `shared_ptr<const InterfaceMap>` snapshot을 사용해 조회 중 데이터가 변경되지 않도록 합니다.
- monitor thread를 종료한 뒤 fd를 닫는 lifecycle 순서를 보장합니다.

### BPF control wrappers

- BPF map, ring buffer, perf buffer의 fd를 RAII 방식으로 관리합니다.
- 기존 pinned object는 `bpf_obj_get()`으로 열고 kernel metadata를 다시 읽습니다.
- 새 object는 생성 후 bpffs에 pin할 수 있습니다.
- map update, lookup, delete, iteration과 event buffer polling을 C++ API로 제공합니다.

이 코드는 `bpftool` CLI를 감싼 wrapper가 아니라 **libbpf 기반 C++ wrapper**입니다. `bpftool`은 실행 결과를 확인하는 진단 도구로만 사용합니다.

### BpfProgLoader

- eBPF object에서 지정된 TC program을 찾고 verifier를 거쳐 로드합니다.
- userspace wrapper가 연 pinned map fd를 `bpf_map__reuse_fd()`로 object에 연결합니다.
- program pin의 소유권을 기록해 자신이 만든 pin만 제거합니다.
- 시작 시 모든 현재 non-loopback NIC에 program을 attach합니다.
- InterfaceLoader가 NIC 변경을 통지하면 최신 snapshot에 attach를 다시 적용합니다.
- 동일한 handle/priority에 현재 program이 이미 붙어 있으면 중복 attach를 생략합니다.
- 종료 시 monitor callback을 먼저 멈추고, 관리 중인 handle/priority에서 현재 program ID와 일치하는 TC filter를 정리합니다.

## Hotplug 동작 범위

이 브랜치에서 동적인 것은 **NIC 구성**입니다.

1. 프로세스 시작 시 현재 NIC snapshot을 읽습니다.
2. 모든 non-loopback NIC에 TC program을 attach합니다.
3. netlink가 link/address 변경을 알리면 snapshot을 다시 만듭니다.
4. BpfProgLoader가 새 snapshot 전체에 idempotent attach를 수행합니다.
5. 새 NIC에는 filter가 추가되고, 이미 적용된 NIC는 유지됩니다.

실행 중 별도의 allow-list를 수정하는 runtime-mutable target policy는 `dynamic-nic-filter-recovery` 브랜치의 실험 범위입니다.

## 요구 사항

- Linux kernel의 eBPF, TC 및 BTF 지원
- 마운트된 bpffs (`/sys/fs/bpf`)
- CMake 3.16 이상
- C++20을 지원하는 C++ compiler
- BPF target을 지원하는 Clang
- libbpf 개발 헤더와 library
- TC attach와 bpffs 접근에 필요한 권한
  - 일반적으로 root로 실행
  - capability를 분리할 경우 환경에 따라 `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` 또는 `CAP_SYS_ADMIN` 필요

저장소의 BPF build 설정과 `vmlinux.h`는 ARM64/Yocto 대상 환경을 기준으로 합니다. 다른 kernel이나 architecture를 대상으로 할 때는 해당 kernel BTF에서 `vmlinux.h`를 다시 생성하고 `tc_bpf/CMakeLists.txt`의 target define을 조정해야 합니다.

## 빌드

Yocto SDK를 사용하는 경우 먼저 SDK environment script를 적용해 compiler와 sysroot를 설정합니다.

```bash
source /path/to/sdk/environment-setup-armv8a-poky-linux
cmake -S . -B build
cmake --build build -j
```

빌드 결과:

```text
build/bpf_control
build/tc_bpf/tc_mirroring.o
```

## 실행

```bash
sudo ./build/bpf_control \
  ./build/tc_bpf/tc_mirroring.o \
  eth0 \
  eth3
```

인자:

```text
bpf_control <bpf-object-path> <source-interface> <destination-interface>
```

두 interface 인자는 예제의 mirror/monitor map 정책을 초기화하는 데 사용됩니다. TC program 자체는 BpfProgLoader가 발견한 모든 non-loopback NIC에 attach됩니다. 두 정책 interface는 프로그램 시작 시 존재해야 합니다.

종료는 `SIGINT` 또는 `SIGTERM`으로 요청합니다. monitor thread와 event polling thread를 합류시킨 뒤 TC filter와 자신이 만든 program pin을 정리합니다.

## 실행 결과 확인

```bash
sudo tc filter show dev eth0 ingress
sudo bpftool prog show
sudo bpftool map show pinned /sys/fs/bpf/mirror_map
sudo bpftool map show pinned /sys/fs/bpf/monitor_map
sudo bpftool map show pinned /sys/fs/bpf/monitor_ringbuf
```

NIC hotplug 동작은 테스트 NIC를 추가하거나 다시 활성화한 뒤 attach 로그와 TC 상태를 비교해 확인할 수 있습니다. 운영 장비에서는 네트워크 연결에 영향을 줄 수 있으므로 격리된 network namespace 또는 테스트 장비에서 수행해야 합니다.

## 디렉터리 구조

```text
include/nic_check/       InterfaceLoader API
include/utils/           BpfProgLoader와 공통 utility API
include/                 BPF map/ring/perf wrapper API
src/nic_check/           netlink monitor와 snapshot 구현
src/utils/               TC program loader 구현
src/                     userspace wrapper와 실행 예제
tc_bpf/                  TC eBPF program, 공유 자료형, BPF build 설정
```

## 현재 제한 사항

- TC attach 대상은 모든 non-loopback NIC이며 runtime allow-list 변경을 지원하지 않습니다.
- hotplug callback에서 attach가 실패하면 로그로 기록하지만 별도 retry worker는 실행하지 않습니다.
- 외부에서 삭제되거나 교체된 TC filter를 주기적으로 검사하는 reconcile loop는 없습니다.
- mirror/monitor map의 예제 정책은 시작 시 전달된 interface의 ifindex를 사용하므로, 해당 NIC가 제거 후 다른 ifindex로 다시 생성되면 정책을 다시 넣어야 합니다.
- 자동화된 unit/integration test는 아직 포함되어 있지 않습니다.
