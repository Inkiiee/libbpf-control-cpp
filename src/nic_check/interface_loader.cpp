/*
Class Name   : interface_loader.cpp
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-08, 프로그램 작성
*/

#include "nic_check/interface_loader.h"
#include "utils/logger.hpp"

#include <ifaddrs.h>
#include <cstring>
#include <cerrno>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <cstdio>
#include <sys/socket.h>

#include <mutex>
#include <memory>

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
}

namespace nic_check{
    std::string InterfaceLoader::mac_to_string(const uint8_t mac[6]) const {
        char buf[18];

        std::snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        return string(buf);
    }

    string InterfaceLoader::get_ip_string_by_sockaddr_in(const struct sockaddr_in* addr) {
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

    string InterfaceLoader::get_mac_string_by_ifname(const std::string& ifname) {
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

    InterfaceLoader::InterfaceLoader(): last_error_{InterfaceError::kNoError}, sock_{-1} {
        sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        if(sock_ < 0){
            const int error_number = errno;
            set_last_error(InterfaceError::kSocketError);
            utils::log("socket(AF_INET, SOCK_DGRAM) failed: " + errno_message(error_number));
            return;
        }

        refresh_interface_list();
    }

    InterfaceLoader::~InterfaceLoader(){
        if(sock_ >= 0)
            ::close(sock_);
    }

    InterfaceError InterfaceLoader::get_last_error() const {
        std::lock_guard<mutex> lock(last_error_mutex_);
        return last_error_;
    }

    void InterfaceLoader::set_last_error(InterfaceError error){
        std::lock_guard<mutex> lock(last_error_mutex_);
        last_error_ = error;
    }

    void InterfaceLoader::refresh_interface_list(){
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

        unordered_map<string, InterfaceInfo> processed;
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
        {
            lock_guard<mutex> lock(interfaces_mutex_);
            interfaces_ = std::move(processed);
        }
        set_last_error(InterfaceError::kNoError);

        utils::log("interface list refreshed: loaded=" + std::to_string(loaded) +
                   " skipped=" + std::to_string(skipped));
    }

    std::uint32_t InterfaceLoader::get_ifindex_by_ifname(const string& ifname){
        {
            lock_guard<mutex> lock(interfaces_mutex_);
            auto info = interfaces_.find(ifname);
            if(info != interfaces_.end()){
                set_last_error(InterfaceError::kNoError);
                return info->second.ifindex;
            }
        }

        set_last_error(InterfaceError::kNotExistIfNameError);
        return 0;
    }
    string InterfaceLoader::get_ifname_by_ifindex(std::uint32_t ifindex){
        {
            lock_guard<mutex> lock(interfaces_mutex_);
            for(const auto& [k, v]: interfaces_)
                if(ifindex == v.ifindex){
                    set_last_error(InterfaceError::kNoError);
                    return k;
                }
        }

        set_last_error(InterfaceError::kNotExistIfIndexError);
        return "";
    }
    optional<InterfaceInfo> InterfaceLoader::get_ifinfo_by_ifname(const std::string& ifname){
        {
            lock_guard<mutex> lock(interfaces_mutex_);
            auto info = interfaces_.find(ifname);
            if(info != interfaces_.end()){
                set_last_error(InterfaceError::kNoError);
                return info->second;
            }
        }

        set_last_error(InterfaceError::kNotExistIfNameError);
        return nullopt;
    }
    optional<InterfaceInfo> InterfaceLoader::get_ifinfo_by_ifindex(std::uint32_t ifindex){
        {
            lock_guard<mutex> lock(interfaces_mutex_);
            for(const auto& [k, v]: interfaces_)
                if(v.ifindex == ifindex){
                    set_last_error(InterfaceError::kNoError);
                    return v;
                }
        }

        set_last_error(InterfaceError::kNotExistIfIndexError);
        return nullopt;
    }
}
