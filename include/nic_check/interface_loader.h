/*
Class Name   : interface_loader.h
@version     : 1.1
@author      : Inkiiee
@modify      : 2026-09-08, 프로그램 작성
               2026-09-10, netlink 변경 모니터링 및 스냅샷 조회 추가
*/

#ifndef INTERFACE_LOADER_H
#define INTERFACE_LOADER_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <netinet/in.h>

namespace nic_check {
    struct InterfaceInfo {
        std::string name;
        std::string mac_address;
        std::string ip_address;
        std::string netmask;
        std::string broadcast_address;
        std::uint32_t ifindex;

        InterfaceInfo(
            const std::string& n, const std::string& m, const std::string& i,
            const std::string& net, const std::string& b, std::uint32_t index
        ): name(n), mac_address(m), ip_address(i), netmask(net), broadcast_address(b), ifindex(index){}
        InterfaceInfo():
            name(""), mac_address(""), ip_address(""), netmask(""), broadcast_address(""), ifindex(0){}
        InterfaceInfo(InterfaceInfo&&) = default;
        InterfaceInfo(const InterfaceInfo&) = default;
        InterfaceInfo& operator=(const InterfaceInfo&) = default;
        InterfaceInfo& operator=(InterfaceInfo&&) = default;
    };

    enum class InterfaceError: std::uint32_t{
        kNoError = 0,
        kGetIfAddrsError = 1,
        kIoctlError,
        kInvalidInterfaceError,
        kSocketError,
        kInetNtoPError,
        kNotExistIfIndexError,
        kNotExistIfNameError,
        kNetlinkSocketError,
        kNetlinkBindError,
        kNetlinkReceiveError,
        kNetlinkOverrunError,
        kWakeFdError,
        kPollError,
    };

    inline constexpr std::string_view interface_loader_error_string(InterfaceError error_code){
        switch (error_code) {
        case InterfaceError::kNoError:
            return "No error";
        case InterfaceError::kGetIfAddrsError:
            return "Failed getting interface info(getifaddrs error)";
        case InterfaceError::kIoctlError:
            return "Failed getting mac address(ioctl error)";
        case InterfaceError::kInvalidInterfaceError:
            return "The Interface is invalid";
        case InterfaceError::kSocketError:
            return "Failed Creating socket(socket error)";
        case InterfaceError::kInetNtoPError:
            return "Failed Transforming IPv4 value to IPv4 String(inet_ntop error)";
        case InterfaceError::kNotExistIfIndexError:
            return "There is Not exists the interface index";
        case InterfaceError::kNotExistIfNameError:
            return "There is Not exists the interface name";
        case InterfaceError::kNetlinkSocketError:
            return "Failed creating netlink socket";
        case InterfaceError::kNetlinkBindError:
            return "Failed binding netlink socket to multicast groups";
        case InterfaceError::kNetlinkReceiveError:
            return "Failed receiving a netlink message";
        case InterfaceError::kNetlinkOverrunError:
            return "Netlink messages were dropped(ENOBUFS); forced a full resync";
        case InterfaceError::kWakeFdError:
            return "Failed creating the monitor wake-up eventfd";
        case InterfaceError::kPollError:
            return "Failed polling the monitor descriptors";
        default:
            return "Unknown error code";
        }
    }

    /*
        인터페이스 목록을 읽어 보관하고, netlink 로 변경을 감시한다.

        조회는 스냅샷(shared_ptr<const InterfaceMap>) 기반이다. refresh 는 새 맵을
        만든 뒤 포인터만 교체하므로,
          - 읽는 쪽은 포인터 하나만 복사한다 (인터페이스 개수와 무관)
          - 스냅샷을 든 동안 그 뷰는 변하지 않는다 (연속 조회의 TOCTOU 제거)
          - refresh 가 읽는 쪽을 막지 않는다 (락 보유가 포인터 대입 한 번)

        refresh 는 refresh_mutex_ 로 직렬화한다. 직렬화하지 않으면 늦게 끝난
        오래된 refresh 가 최신 결과를 덮어쓸 수 있다.
    */
    class InterfaceLoader {
    public:
        using InterfaceMap = std::unordered_map<std::string, InterfaceInfo>;
        using SnapshotPtr = std::shared_ptr<const InterfaceMap>;
        // 변경 통지. 항상 락 밖에서 호출하므로 안에서 loader 를 다시 불러도 안전하다.
        using ChangeHandler = std::function<void(SnapshotPtr)>;

        // netlink 는 한 번의 논리적 변경에도 이벤트를 여러 개 보낸다
        // (ip link set up -> NEWLINK x2 + NEWADDR ...). 이만큼 조용해진 뒤 한 번만 refresh 한다.
        static constexpr std::chrono::milliseconds kDefaultDebounce{150};

        explicit InterfaceLoader(std::chrono::milliseconds debounce = kDefaultDebounce);
        ~InterfaceLoader();

        // 스레드와 fd 를 소유하므로 복사/이동을 막는다.
        InterfaceLoader(const InterfaceLoader&) = delete;
        InterfaceLoader& operator=(const InterfaceLoader&) = delete;
        InterfaceLoader(InterfaceLoader&&) = delete;
        InterfaceLoader& operator=(InterfaceLoader&&) = delete;

        // 스레드 계약: 조회 함수와 request_refresh() 는 아무 스레드에서나 호출해도
        // 되지만, start_monitor()/stop_monitor() 는 한 스레드에서만 호출한다
        // (내부 fd 와 jthread 를 교체하므로).

        // netlink 감시 시작. on_change 는 refresh 가 끝날 때마다 락 밖에서 호출된다.
        bool start_monitor(ChangeHandler on_change = {});
        void stop_monitor();
        bool is_monitoring() const;

        // 즉시 읽지 않고 "다시 읽어야 한다"고 알린다. 감시 중이면 워커가 debounce 후
        // 처리하고, 감시 중이 아니면 호출 스레드에서 바로 refresh 한다.
        void request_refresh();

        SnapshotPtr snapshot() const;

        std::uint32_t get_ifindex_by_ifname(const std::string& ifname) const;
        std::string get_ifname_by_ifindex(std::uint32_t ifindex) const;
        std::optional<InterfaceInfo> get_ifinfo_by_ifname(const std::string& ifname) const;
        std::optional<InterfaceInfo> get_ifinfo_by_ifindex(std::uint32_t ifindex) const;

        InterfaceError get_last_error() const;

    private:
        // 락을 쥔 채 목록을 새로 읽어 out 에 넣는다. 콜백은 여기서 부르지 않는다.
        void reload_snapshot(SnapshotPtr& out);
        void refresh_interface_list();
        void monitor_loop(std::stop_token stop);
        bool open_netlink();
        void close_fd(int& fd);
        // 관심 있는 변경이 있었으면 true. 어차피 전체를 다시 읽으므로 속성은 파싱하지 않는다.
        bool drain_netlink();
        void drain_wake();
        void wake_monitor();
        void notify_change(const SnapshotPtr& current);

        void set_last_error(InterfaceError error) const;
        std::string mac_to_string(const std::uint8_t mac[6]) const ;
        std::string get_ip_string_by_sockaddr_in(const struct sockaddr_in* addr) const ;
        std::string get_mac_string_by_ifname(const std::string& ifname) const ;

        SnapshotPtr interfaces_;
        mutable std::mutex interfaces_mutex_;

        mutable InterfaceError last_error_;
        mutable std::mutex last_error_mutex_;

        std::mutex refresh_mutex_;

        ChangeHandler on_change_;
        mutable std::mutex handler_mutex_;

        std::chrono::milliseconds debounce_;
        std::atomic<bool> dirty_;

        int sock_;      // MAC 조회용 ioctl 소켓. refresh 안에서만 쓰이고 직렬화되어 있다.
        int nl_sock_;   // NETLINK_ROUTE 감시 소켓
        int wake_fd_;   // 감시 루프를 깨우는 eventfd

        std::jthread monitor_thread_;
    };
}

#endif // INTERFACE_LOADER_H
