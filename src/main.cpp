#include <iostream>
#include <string>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <vector>
#include <thread>
#include <stop_token>
#include <cerrno>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "bpf_map_control.h"
#include "bpf_ring_buffer_control.h"
#include "bpf_tool/bpf_prog_loader.h"
#include "bpf_tool/bpf_attacher.h"
#include "bpf_tool/bpf_attach_manager.h"
#include "utils/logger.hpp"
#include "tc_bpf/tc_comm.h"

using namespace std;
using namespace utils;
using namespace bpf_tool;
using namespace bpf_control;
using namespace nic_check;

enum class EventType: int{
    kStop = 0,
};

string ip_to_string(std::uint32_t ip){
    char ip_str[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN) == nullptr) {
        return "0.0.0.0"; // 변환 실패 시 예외 처리
    }

    return string(ip_str);
}

InterfaceLoader in;

// 핀이 이미 있으면 그것을 열고, 없을 때만 새로 만들어 핀한다.
template <class BpfObject>
bool open_or_create(BpfObject& object, const string& name, const string& pin_path){
    if(object.open(true, pin_path) == BpfControlErrorCode::kNoError){
        utils::log("reuse pinned " + name + ": " + pin_path);
        return true;
    }

    const auto opened = object.open();
    if(opened != BpfControlErrorCode::kNoError){
        utils::log(name + " open failed: " + string(bpf_control_error_string(opened)));
        return false;
    }

    const auto pinned = object.pin(pin_path);
    if(pinned != BpfControlErrorCode::kNoError){
        utils::log(name + " pin failed: " + string(bpf_control_error_string(pinned)));
        return false;
    }

    utils::log("created and pinned " + name + ": " + pin_path);
    return true;
}

void set_monitoring_target(BpfMapControl& map, const string& ifname){
    auto snapshot = in.snapshot();
    auto info = snapshot->find(ifname);
    if(info == snapshot->end()){
        utils::log("monitoring target not found: " + ifname);
        return;
    }

    monitor_key key = info->second.ifindex;
    monitor_value enabled = 1;

    const auto rc = map.update(&key, &enabled);
    if(rc != BpfControlErrorCode::kNoError){
        utils::log("monitor_map update failed(" + ifname + "): " +
                   string(bpf_control_error_string(rc)));
        return;
    }

    utils::log("monitoring on: " + ifname + " (ifindex=" + to_string(key) + ")");
}

void set_mirroring(BpfMapControl& map, const string& src_ifname, const string& dst_ifname){
    auto snapshot = in.snapshot();
    auto src_info = snapshot->find(src_ifname);
    auto dst_info = snapshot->find(dst_ifname);
    if(src_info == snapshot->end() || dst_info == snapshot->end()){
        utils::log("mirroring target not found: " +
                   (src_info == snapshot->end() ? src_ifname : dst_ifname));
        return;
    }

    mirror_key key = src_info->second.ifindex;

    // lookup 이 실패하면 값이 채워지지 않는다. 0 으로 시작해
    // dst_ifindexes[] 의 스택 쓰레기가 커널로 넘어가지 않게 한다.
    mirror_value value{};
    if(map.lookup(&key, &value) != BpfControlErrorCode::kNoError)
        value = mirror_value{};

    if(value.dst_ifindex_count >= MIRRORING_MAX_INSTANCES){
        utils::log("mirror targets are full for " + src_ifname);
        return;
    }

    value.enabled = 1;
    value.dst_ifindexes[value.dst_ifindex_count] = dst_info->second.ifindex;
    ++value.dst_ifindex_count;

    const auto rc = map.update(&key, &value);
    if(rc != BpfControlErrorCode::kNoError){
        utils::log("mirror_map update failed(" + src_ifname + " -> " + dst_ifname + "): " +
                   string(bpf_control_error_string(rc)));
        return;
    }

    utils::log("mirroring: " + src_ifname + " -> " + dst_ifname +
               " (targets=" + to_string(value.dst_ifindex_count) + ")");
}

int main(){
    sigset_t termination_signals {};
    sigemptyset(&termination_signals);
    sigaddset(&termination_signals, SIGINT);
    sigaddset(&termination_signals, SIGTERM);
    const int mask_error = pthread_sigmask(SIG_BLOCK, &termination_signals, nullptr);
    if(mask_error != 0){
        error_code ec(-mask_error, generic_category());
        utils::log("signals block failed: " + ec.message());
        return mask_error;
    }

    BpfMapControl mirror_map("mirror_map", sizeof(mirror_key), sizeof(mirror_value), MIRRORING_MAX_INSTANCES);
    BpfMapControl monitor_map("monitor_map", sizeof(monitor_key), sizeof(monitor_value), MONITORING_MAX_INSTANCES);
    BpfRingBufferControl monitor_ringbuf("monitor_ringbuf", MONITOR_RINGBUF_SIZE);

    if(!open_or_create(mirror_map, "mirror_map", "/sys/fs/bpf/mirror_map"))
        return 1;
    if(!open_or_create(monitor_map, "monitor_map", "/sys/fs/bpf/monitor_map"))
        return 1;
    if(!open_or_create(monitor_ringbuf, "monitor_ringbuf", "/sys/fs/bpf/monitor_ringbuf"))
        return 1;

    set_mirroring(mirror_map, "eth0", "eth3");
    set_mirroring(mirror_map, "eth3", "eth0");
    set_monitoring_target(monitor_map, "eth0");
    set_monitoring_target(monitor_map, "eth3");

    std::vector<BpfBase*> pinned {&mirror_map, &monitor_map, &monitor_ringbuf};
    auto [bpf_prog, error] = BpfProgLoader::load_program("/home/root/tc_mirrring.o", "tc_mirrring", pinned);
    if(error != BpfProgLoaderError::kNoError){
        utils::log("Prog load error");
        return -1;
    }
    
    auto& manager = BpfAttachManager::get_instance();
    auto attacher = manager.create_attacher(bpf_prog, {
        .priority = 100,
        .handle = 1,
        .is_ingress = true
    });

    attacher->add_target("eth0");
    attacher->add_target("eth1");

    atomic<bool> is_running = true;
    condition_variable event_cv;
    mutex event_mutex;
    std::vector<EventType> events;

    auto notify = [&event_mutex, &events, &event_cv](EventType ev){
        {
            lock_guard<mutex> lock(event_mutex);
            events.push_back(ev);
        }
        event_cv.notify_one();
    };

    jthread signal_wait_thread;
    signal_wait_thread = jthread([&notify, &termination_signals](stop_token token){
        while(!token.stop_requested()){
            timespec timeout {};
            timeout.tv_nsec = 200'000'000L;

            const int received_signal = sigtimedwait(&termination_signals, nullptr, &timeout);
            if(received_signal == SIGINT || received_signal == SIGTERM){
                utils::log("SIGINT or SIGTERM received");
                notify(EventType::kStop);
                break;
            }

            if(received_signal == -1){
                const int snap_error = errno;
                if((snap_error == EAGAIN || snap_error == EINTR)) continue;

                utils::log("wait signals error");
                notify(EventType::kStop);
                break;
            }
        }
    });

    jthread monitor_thread;
    monitor_thread = jthread([&monitor_ringbuf](stop_token token){
        BpfRingBufferControl::ring_buffer_sample_callback 
            monitor_cb=[](void *ctx, void *data, size_t size) -> int
        {
            if(size < sizeof(monitor_event)){
                utils::log("MOnitor error, received event size is too small");
                return -1;
            }

            monitor_event * event = reinterpret_cast<monitor_event*>(data);
            const string&& src = ip_to_string(event->src_ip);
            const string&& dst = ip_to_string(event->dst_ip);
            utils::log(src + " -> " + dst);
            return 0;
        };

        monitor_ringbuf.set_callback(monitor_cb);
        monitor_ringbuf.event_buffer_create();
        utils::log("Monitoring start");
        while(!token.stop_requested()){
            monitor_ringbuf.poll(100);
        }
    });

    while(is_running.load()){
        vector<EventType> pendings;
        {
            unique_lock<mutex> lock(event_mutex);
            event_cv.wait(lock, [&events, &is_running]{
                return !is_running.load() || !events.empty();
            });

            pendings.swap(events);
        }

        for(const auto ev: pendings){
            if(ev == EventType::kStop){
                is_running.store(false);
            }
        }
    }

    if(signal_wait_thread.joinable()){
        signal_wait_thread.request_stop();
        signal_wait_thread.join();
    }
    if(monitor_thread.joinable()){
        monitor_thread.request_stop();
        monitor_thread.join();
    }

    return 0;
}