/*
Class Name   : interface_loader.cpp
@version     : 1.1
@author      : Inkiiee
@modify      : 2026-09-08, 프로그램 작성
               2026-09-10, netlink 변경 모니터링 및 스냅샷 조회 추가
*/

#include "nic_check/interface_loader.h"
#include "utils/logger.hpp"

#include <ifaddrs.h>
#include <cstring>
#include <cerrno>
// net/if.h 는 linux/* 보다 먼저 와야 한다. 반대로 두면 커널 uapi 헤더가
// struct ifreq 등을 다시 정의해 충돌한다(__UAPI_DEF_IF_* 가드가 이 순서를 전제한다).
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <cstdio>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <algorithm>
#include <mutex>
#include <memory>
#include <utility>

using namespace std;

namespace{
    // strerror 는 정적 버퍼를 반환해 스레드 안전하지 않다. 이 클래스는 뮤텍스로
    // 멀티스레드 사용을 전제하므로 strerror_r 을 쓴다.
    // g++ 는 리눅스에서 _GNU_SOURCE 를 정의하므로 char* 를 돌려주는 GNU 버전이
    // 선택된다. 엄격 POSIX 로 빌드하면 int 를 반환해 컴파일 단계에서 드러난다.
    std::string errno_message(int error_number){
        char buffer[128];
        return std::string(::strerror_r(error_number, buffer, sizeof(buffer)));
    }

    // netlink 수신 버퍼. 한 번에 여러 메시지가 담겨 온다.
    constexpr std::size_t kNetlinkBufferSize = 8192;
    // 버스트 때 ENOBUFS 로 이벤트를 잃는 빈도를 줄인다.
    constexpr int kNetlinkReceiveBufferBytes = 1024 * 1024;
}

namespace nic_check{
    std::string InterfaceLoader::mac_to_string(const uint8_t mac[6]) const {
        char buf[18];

        std::snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        return string(buf);
    }

    string InterfaceLoader::get_ip_string_by_sockaddr_in(const struct sockaddr_in* addr) const {
        if(!addr) return "";

        char buf_addr_string[INET_ADDRSTRLEN];
        if(::inet_ntop(AF_INET, &(addr->sin_addr), buf_addr_string, sizeof(buf_addr_string)) == NULL){
            const int error_number = errno;
            set_last_error(InterfaceError::kInetNtoPError);
            utils::log("inet_ntop failed: " + errno_message(error_number));
            return "";
        }

        return string(buf_addr_string);
    }

    string InterfaceLoader::get_mac_string_by_ifname(const std::string& ifname) const {
        struct ifreq ifr;
        std::memset(&ifr, 0x00, sizeof(ifr));

        size_t ifname_len = std::min(static_cast<std::size_t>(IFNAMSIZ - 1), ifname.length());
        std::strncpy(ifr.ifr_name, ifname.data(), ifname_len);

        if(::ioctl(sock_, SIOCGIFHWADDR, &ifr) != 0){
            const int error_number = errno;
            set_last_error(InterfaceError::kIoctlError);
            utils::log("SIOCGIFHWADDR failed on " + ifname + ": " + errno_message(error_number));
            return "";
        }

        std::uint8_t * mac_buf = reinterpret_cast<std::uint8_t*>(ifr.ifr_hwaddr.sa_data);
        return mac_to_string(mac_buf);
    }

    InterfaceLoader::InterfaceLoader(std::chrono::milliseconds debounce)
        : interfaces_{std::make_shared<const InterfaceMap>()},
          last_error_{InterfaceError::kNoError},
          debounce_{debounce},
          dirty_{false},
          sock_{-1},
          nl_sock_{-1},
          wake_fd_{-1}
    {
        sock_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if(sock_ < 0){
            const int error_number = errno;
            set_last_error(InterfaceError::kSocketError);
            utils::log("socket(AF_INET, SOCK_DGRAM) failed: " + errno_message(error_number));
            return;
        }

        refresh_interface_list();
    }

    InterfaceLoader::~InterfaceLoader(){
        stop_monitor();
        close_fd(sock_);
    }

    void InterfaceLoader::close_fd(int& fd){
        if(fd < 0) return;

        if(::close(fd) < 0){
            const int error_number = errno;
            utils::log("close failed: " + errno_message(error_number));
        }
        fd = -1;
    }

    InterfaceError InterfaceLoader::get_last_error() const {
        std::lock_guard<mutex> lock(last_error_mutex_);
        return last_error_;
    }

    void InterfaceLoader::set_last_error(InterfaceError error) const {
        std::lock_guard<mutex> lock(last_error_mutex_);
        last_error_ = error;
    }

    // ------------------------------------------------------------ 모니터링

    bool InterfaceLoader::open_netlink(){
        nl_sock_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
        if(nl_sock_ < 0){
            const int error_number = errno;
            set_last_error(InterfaceError::kNetlinkSocketError);
            utils::log("netlink socket failed: " + errno_message(error_number));
            return false;
        }

        // 실패해도 치명적이지 않다. ENOBUFS 가 잦아질 뿐이고 그건 재동기화로 복구된다.
        if(::setsockopt(nl_sock_, SOL_SOCKET, SO_RCVBUF,
                        &kNetlinkReceiveBufferBytes, sizeof(kNetlinkReceiveBufferBytes)) < 0){
            const int error_number = errno;
            utils::log("SO_RCVBUF failed(continuing): " + errno_message(error_number));
        }

        struct sockaddr_nl addr;
        std::memset(&addr, 0x00, sizeof(addr));
        addr.nl_family = AF_NETLINK;
        // 링크 상태와 IPv4 주소 변경만 구독한다. IPv6 를 빼면 그만큼 이벤트도 줄어든다.
        addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

        if(::bind(nl_sock_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0){
            const int error_number = errno;
            set_last_error(InterfaceError::kNetlinkBindError);
            utils::log("netlink bind failed: " + errno_message(error_number));
            close_fd(nl_sock_);
            return false;
        }

        return true;
    }

    bool InterfaceLoader::start_monitor(ChangeHandler on_change){
        if(monitor_thread_.joinable()){
            utils::log("monitor is already running");
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(handler_mutex_);
            on_change_ = std::move(on_change);
        }

        wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if(wake_fd_ < 0){
            const int error_number = errno;
            set_last_error(InterfaceError::kWakeFdError);
            utils::log("eventfd failed: " + errno_message(error_number));
            return false;
        }

        if(!open_netlink()){
            close_fd(wake_fd_);
            return false;
        }

        // 생성자의 refresh 와 감시 시작 사이에 일어난 변경을 놓치지 않도록 한 번 읽는다.
        dirty_.store(true, std::memory_order_release);
        wake_monitor();

        monitor_thread_ = std::jthread([this](std::stop_token stop){ monitor_loop(stop); });
        utils::log("interface monitor started(debounce=" +
                   std::to_string(debounce_.count()) + "ms)");
        return true;
    }

    void InterfaceLoader::stop_monitor(){
        if(monitor_thread_.joinable()){
            // request_stop 이 stop_callback 을 거쳐 eventfd 를 건드려 poll 을 깨운다.
            monitor_thread_.request_stop();
            monitor_thread_.join();
            utils::log("interface monitor stopped");
        }

        close_fd(nl_sock_);
        close_fd(wake_fd_);

        {
            std::lock_guard<std::mutex> lock(handler_mutex_);
            on_change_ = nullptr;
        }
    }

    bool InterfaceLoader::is_monitoring() const {
        return monitor_thread_.joinable();
    }

    void InterfaceLoader::wake_monitor(){
        if(wake_fd_ < 0) return;

        const std::uint64_t one = 1;
        if(::write(wake_fd_, &one, sizeof(one)) < 0){
            const int error_number = errno;
            // EAGAIN 은 카운터가 이미 가득 찼다는 뜻이라 어차피 깨어난다.
            if(error_number != EAGAIN)
                utils::log("failed waking monitor: " + errno_message(error_number));
        }
    }

    void InterfaceLoader::drain_wake(){
        std::uint64_t value = 0;
        while(::read(wake_fd_, &value, sizeof(value)) == static_cast<ssize_t>(sizeof(value))){
            // EFD_NONBLOCK 이라 비면 EAGAIN 으로 빠진다.
        }
    }

    void InterfaceLoader::request_refresh(){
        if(monitor_thread_.joinable()){
            dirty_.store(true, std::memory_order_release);
            wake_monitor();
            return;
        }

        // 감시 중이 아니면 처리해 줄 워커가 없으므로 호출 스레드에서 바로 읽는다.
        refresh_interface_list();
    }

    bool InterfaceLoader::drain_netlink(){
        bool changed = false;
        char buffer[kNetlinkBufferSize];

        for(;;){
            struct sockaddr_nl peer;
            std::memset(&peer, 0x00, sizeof(peer));

            struct iovec iov;
            iov.iov_base = buffer;
            iov.iov_len = sizeof(buffer);

            struct msghdr message;
            std::memset(&message, 0x00, sizeof(message));
            message.msg_name = &peer;
            message.msg_namelen = sizeof(peer);
            message.msg_iov = &iov;
            message.msg_iovlen = 1;

            const ssize_t received = ::recvmsg(nl_sock_, &message, 0);
            if(received < 0){
                const int error_number = errno;
                if(error_number == EINTR) continue;
                if(error_number == EAGAIN || error_number == EWOULDBLOCK) break;
                if(error_number == ENOBUFS){
                    // 커널 버퍼가 넘쳐 이벤트가 유실됐다. 증분을 믿을 수 없으니
                    // 전체 재동기화로 따라잡는다. 이걸 그냥 넘기면 이 시점 이후
                    // 상태가 영구히 어긋난다.
                    set_last_error(InterfaceError::kNetlinkOverrunError);
                    utils::log("netlink ENOBUFS: events lost, forcing full resync");
                    changed = true;
                    continue;
                }

                set_last_error(InterfaceError::kNetlinkReceiveError);
                utils::log("netlink recvmsg failed: " + errno_message(error_number));
                break;
            }
            if(received == 0) break;

            // 잘려 들어온 메시지는 신뢰할 수 없으니 역시 재동기화한다.
            if(message.msg_flags & MSG_TRUNC){
                utils::log("netlink message truncated, forcing full resync");
                changed = true;
                continue;
            }

            // 어차피 전체를 다시 읽으므로 속성은 파싱하지 않고 종류만 본다.
            int length = static_cast<int>(received);
            for(struct nlmsghdr* header = reinterpret_cast<struct nlmsghdr*>(buffer);
                NLMSG_OK(header, length);
                header = NLMSG_NEXT(header, length))
            {
                switch(header->nlmsg_type){
                case RTM_NEWLINK:
                case RTM_DELLINK:
                case RTM_NEWADDR:
                case RTM_DELADDR:
                    changed = true;
                    break;
                case NLMSG_ERROR: {
                    const auto* error = reinterpret_cast<const struct nlmsgerr*>(NLMSG_DATA(header));
                    utils::log("netlink error message: " + errno_message(-error->error));
                    break;
                }
                default:
                    break;
                }
            }
        }

        return changed;
    }

    void InterfaceLoader::monitor_loop(std::stop_token stop){
        // stop_token 만으로는 poll 에서 블록된 스레드를 못 깨운다. eventfd 로 깨운다.
        std::stop_callback wake_on_stop(stop, [this]{ wake_monitor(); });

        bool pending = false;
        std::chrono::steady_clock::time_point deadline{};

        while(!stop.stop_requested()){
            // 대기 중인 변경이 없으면 무한 대기, 있으면 남은 debounce 만큼만 기다린다.
            int timeout_ms = -1;
            if(pending){
                const auto now = std::chrono::steady_clock::now();
                timeout_ms = (now >= deadline) ? 0 : static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            }

            struct pollfd fds[2];
            fds[0].fd = nl_sock_;  fds[0].events = POLLIN; fds[0].revents = 0;
            fds[1].fd = wake_fd_;  fds[1].events = POLLIN; fds[1].revents = 0;

            const int ready = ::poll(fds, 2, timeout_ms);
            if(ready < 0){
                const int error_number = errno;
                if(error_number == EINTR) continue;

                set_last_error(InterfaceError::kPollError);
                utils::log("poll failed: " + errno_message(error_number));
                break;
            }
            if(stop.stop_requested()) break;

            if(fds[1].revents & POLLIN){
                drain_wake();
                // 외부 request_refresh() 요청도 debounce 를 함께 태운다.
                if(dirty_.exchange(false, std::memory_order_acq_rel)){
                    pending = true;
                    deadline = std::chrono::steady_clock::now() + debounce_;
                }
            }

            if(fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)){
                set_last_error(InterfaceError::kNetlinkReceiveError);
                utils::log("netlink socket entered an error state, stopping monitor");
                break;
            }

            if(fds[0].revents & POLLIN){
                // 이벤트가 올 때마다 deadline 을 미뤄, 버스트가 끝난 뒤 한 번만 읽는다.
                if(drain_netlink()){
                    pending = true;
                    deadline = std::chrono::steady_clock::now() + debounce_;
                }
            }

            if(pending && std::chrono::steady_clock::now() >= deadline){
                pending = false;
                refresh_interface_list();
            }
        }
    }

    void InterfaceLoader::notify_change(const SnapshotPtr& current){
        ChangeHandler handler;
        {
            std::lock_guard<std::mutex> lock(handler_mutex_);
            handler = on_change_;
        }
        if(!handler) return;

        // 콜백 안에서 loader 를 다시 부를 수 있으므로 어떤 락도 쥐지 않은 채 호출한다.
        // std::mutex 는 재귀가 아니라 락을 쥐고 부르면 데드락이다.
        try{
            handler(current);
        } catch(const std::exception& e){
            utils::log(std::string("change handler threw: ") + e.what());
        } catch(...){
            utils::log("change handler threw an unknown exception");
        }
    }

    // -------------------------------------------------------------- 갱신

    void InterfaceLoader::refresh_interface_list(){
        // 콜백은 refresh_mutex_ 를 놓은 뒤에 부른다. 쥔 채로 부르면 콜백이
        // request_refresh() 를 호출했을 때 같은 뮤텍스를 다시 잡아 데드락이다.
        SnapshotPtr next;
        reload_snapshot(next);
        if(next) notify_change(next);
    }

    void InterfaceLoader::reload_snapshot(SnapshotPtr& out){
        // 전체를 직렬화한다. 그러지 않으면 늦게 끝난 오래된 refresh 가 최신 결과를
        // 덮어쓸 수 있다(getifaddrs 는 락 밖에서 도는데 반영 순서는 보장되지 않는다).
        std::lock_guard<std::mutex> refresh_lock(refresh_mutex_);

        // 생성자에서 소켓 확보에 실패했으면 MAC 조회가 전부 EBADF 로 실패해
        // 빈 목록을 kNoError 로 덮어쓰게 된다. 시작 지점에서 막는다.
        if(sock_ < 0){
            set_last_error(InterfaceError::kSocketError);
            utils::log("refresh aborted: ioctl socket is not available");
            return;
        }

        struct ifaddrs* ifaddr = nullptr;
        if(::getifaddrs(&ifaddr) == -1){
            const int error_number = errno;
            set_last_error(InterfaceError::kGetIfAddrsError);
            utils::log("getifaddrs failed: " + errno_message(error_number));
            return;
        }
        unique_ptr<struct ifaddrs, decltype(&::freeifaddrs)> ifaddr_ptr(ifaddr, ::freeifaddrs);

        // 개별 실패 사유는 로그에만 남는다(마지막 set_last_error 가 덮으므로).
        // 건너뛴 개수는 요약 로그로 드러낸다.
        size_t skipped = 0;

        InterfaceMap processed;
        for(struct ifaddrs* ifa = ifaddr_ptr.get(); ifa; ifa = ifa->ifa_next){
            if(ifa->ifa_addr == nullptr) continue;

            const string ifname = ifa->ifa_name;
            // 같은 인터페이스의 두 번째 주소는 정상 상황이라 로그를 남기지 않는다.
            if(processed.contains(ifname)) continue;

            if(ifa->ifa_addr->sa_family != AF_INET || ifa->ifa_flags & IFF_LOOPBACK) continue;

            const std::uint32_t ifindex = ::if_nametoindex(ifname.c_str());
            if(ifindex == 0){
                const int error_number = errno;
                ++skipped;
                utils::log("skip " + ifname + ": if_nametoindex failed: " + errno_message(error_number));
                continue;
            }

            auto mac = get_mac_string_by_ifname(ifname);
            if(mac.empty()){
                ++skipped;
                utils::log("skip " + ifname + ": mac address unavailable");
                continue;
            }

            auto device_ip = get_ip_string_by_sockaddr_in(reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_addr));
            auto subnet_ip = get_ip_string_by_sockaddr_in(reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_netmask));

            string broadcast_ip;
            if(ifa->ifa_flags & IFF_BROADCAST)
                broadcast_ip = get_ip_string_by_sockaddr_in(reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_broadaddr));
            else
                broadcast_ip = "N/A";

            if(device_ip.empty() || subnet_ip.empty() || broadcast_ip.empty()){
                ++skipped;
                utils::log("skip " + ifname + ": address conversion failed (ip=" +
                    (device_ip.empty() ? "fail" : "ok") + " netmask=" +
                    (subnet_ip.empty() ? "fail" : "ok") + " broadcast=" +
                    (broadcast_ip.empty() ? "fail" : "ok") + ")");
                continue;
            }

            InterfaceInfo info;
            info.name = ifname;
            info.ifindex = ifindex;
            info.mac_address = std::move(mac);
            info.ip_address = std::move(device_ip);
            info.broadcast_address = std::move(broadcast_ip);
            info.netmask = std::move(subnet_ip);
            processed.emplace(ifname, std::move(info));
        }

        const size_t loaded = processed.size();

        // 새 맵을 통째로 만들고 포인터만 교체한다. 락 보유는 대입 한 번이다.
        auto next = std::make_shared<const InterfaceMap>(std::move(processed));
        {
            lock_guard<mutex> lock(interfaces_mutex_);
            interfaces_ = next;
        }
        set_last_error(InterfaceError::kNoError);

        utils::log("interface list refreshed: loaded=" + std::to_string(loaded) +
                   " skipped=" + std::to_string(skipped));

        out = std::move(next);
    }

    // -------------------------------------------------------------- 조회

    InterfaceLoader::SnapshotPtr InterfaceLoader::snapshot() const {
        lock_guard<mutex> lock(interfaces_mutex_);
        return interfaces_;
    }

    std::uint32_t InterfaceLoader::get_ifindex_by_ifname(const string& ifname) const {
        const auto current = snapshot();

        auto info = current->find(ifname);
        if(info != current->end()){
            set_last_error(InterfaceError::kNoError);
            return info->second.ifindex;
        }

        set_last_error(InterfaceError::kNotExistIfNameError);
        return 0;
    }

    string InterfaceLoader::get_ifname_by_ifindex(std::uint32_t ifindex) const {
        const auto current = snapshot();

        for(const auto& [k, v]: *current)
            if(ifindex == v.ifindex){
                set_last_error(InterfaceError::kNoError);
                return k;
            }

        set_last_error(InterfaceError::kNotExistIfIndexError);
        return "";
    }

    optional<InterfaceInfo> InterfaceLoader::get_ifinfo_by_ifname(const std::string& ifname) const {
        const auto current = snapshot();

        auto info = current->find(ifname);
        if(info != current->end()){
            set_last_error(InterfaceError::kNoError);
            return info->second;
        }

        set_last_error(InterfaceError::kNotExistIfNameError);
        return nullopt;
    }

    optional<InterfaceInfo> InterfaceLoader::get_ifinfo_by_ifindex(std::uint32_t ifindex) const {
        const auto current = snapshot();

        for(const auto& [k, v]: *current)
            if(v.ifindex == ifindex){
                set_last_error(InterfaceError::kNoError);
                return v;
            }

        set_last_error(InterfaceError::kNotExistIfIndexError);
        return nullopt;
    }
}
