#include <iostream>
#include <string>

#include "bpf_map_control.h"
#include "bpf_ring_buffer_control.h"
#include "utils/bpf_prog_loader.h"
#include "utils/logger.hpp"

#include "tc_bpf/tc_comm.h"

using namespace std;
using namespace utils;
using namespace bpf_control;

int main(){
    BpfMapControl mirror_map("mirror_map", sizeof(mirror_key), sizeof(mirror_value), MIRRORING_MAX_INSTANCES);
    BpfMapControl monitor_map("monitor_map", sizeof(monitor_key), sizeof(monitor_value), MONITORING_MAX_INSTANCES);
    BpfRingBufferControl monitor_ringbuf("monitor_ringbuf", MONITOR_RINGBUF_SIZE);

    mirror_map.open();
    monitor_map.open();
    monitor_ringbuf.open();

    mirror_map.pin("/sys/fs/bpf/mirror_map");
    monitor_map.pin("/sys/fs/bpf/monitor_map");
    monitor_ringbuf.pin("/sys/fs/bpf/monitor_ringbuf");

    BpfProgLoader loader("/home/root/tc_mirroring.o");
    std::vector<string> pinned {"mirror_map", "monitor_map", "monitor_ringbuf"};
    loader.load_prog(tc_mirroring, pinned);

    for(;;){}

    return 0;
}