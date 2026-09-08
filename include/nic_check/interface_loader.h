/*
Class Name   : interface_loader.h
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-08, 프로그램 작성
*/

#ifndef INTERFACE_LOADER_H
#define INTERFACE_LOADER_H

#include <string>
#include <cstdint>
#include <unordered_map>
#include <optional>
#include <mutex>
#include <string_view>
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
        default:
            return "Unknown error code";
        }
    }

    class InterfaceLoader {
    public:
        InterfaceLoader();
        ~InterfaceLoader();

        void refresh_interface_list();
        InterfaceError get_last_error() const ;

        std::uint32_t get_ifindex_by_ifname(const std::string& ifname);
        std::string get_ifname_by_ifindex(std::uint32_t ifindex);
        std::optional<InterfaceInfo> get_ifinfo_by_ifname(const std::string& ifname);
        std::optional<InterfaceInfo> get_ifinfo_by_ifindex(std::uint32_t ifindex);
    private:
        std::unordered_map<std::string, InterfaceInfo> interfaces_;
        mutable std::mutex interfaces_mutex_;
        mutable std::mutex last_error_mutex_;
        InterfaceError last_error_;
        int sock_;

        void set_last_error(InterfaceError error);
        std::string mac_to_string(const std::uint8_t mac[6]) const ;
        std::string get_ip_string_by_sockaddr_in(const struct sockaddr_in* addr);
        std::string get_mac_string_by_ifname(const std::string& ifname);
    };
}

#endif // INTERFACE_LOADER_H