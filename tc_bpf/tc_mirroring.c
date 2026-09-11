#include "vmlinux.h"

#include "tc_comm.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define ETH_P_IP 0x0800 /* IPv4 */
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(mirror_key));
    __uint(value_size, sizeof(struct mirror_value));
    __uint(max_entries, MIRRORING_MAX_INSTANCES);
    __uint(map_flags, 0);
} mirror_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(monitor_key));
    __uint(value_size, sizeof(monitor_value));
    __uint(max_entries, MONITORING_MAX_INSTANCES);
    __uint(map_flags, 0);
} monitor_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MONITOR_RINGBUF_SIZE);
} monitor_ringbuf SEC(".maps");

struct custom_vlan_hdr {
    __be16 tci;
    __be16 encapsulated_proto;
};

static __always_inline struct ethhdr *parse_ethhdr(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if((void *)(eth + 1) > data_end)
        return NULL;
    
    return eth;
}

static void* parse_ether_type_and_next(struct ethhdr *eth, void *data_end, __u16 *type){
    __u16 proto = bpf_ntohs(eth->h_proto);
    struct custom_vlan_hdr *vh = (void *)(eth + 1);

#pragma unroll
    for (int i = 0; i < 3; i++) {
        if(proto != ETH_P_8021Q &&
            proto != ETH_P_8021AD)
            break;

        if((void *)(vh + 1) > data_end)
            return NULL;

        proto = bpf_ntohs(vh->encapsulated_proto);
        vh++;
    }

    // VLAN depth > 3 -> drop
    if(proto == ETH_P_8021Q || proto == ETH_P_8021AD)
        return NULL;

    *type = proto;
    return (void *)vh;
}

static __always_inline struct iphdr *parse_iphdr(void *ip_start, void *data_end) {
    struct iphdr *ip = ip_start;
    if((void *)(ip + 1) > data_end)
        return NULL;

    if(ip->version != 4) 
        return NULL; // Not IPv4

    if(ip->ihl < 5)
        return NULL; // Invalid header length

    if((void *)ip + (ip->ihl * 4) > data_end)
        return NULL; // Header extends beyond packet data

    return ip;
}

static __always_inline void mirroring(struct __sk_buff *skb){
    __u32 in_ifindex = skb->ifindex;
    struct mirror_value *mirror_val = bpf_map_lookup_elem(&mirror_map, &in_ifindex);

    if(!mirror_val || !mirror_val->enabled) return;

    __u32 count = mirror_val->dst_ifindex_count;
    if(count > MIRRORING_MAX_INSTANCES)
        return;
    
    for(__u32 i = 0; i < MIRRORING_MAX_INSTANCES; i++){
        if(i >= count) break;

        __u32 dst_ifindex = mirror_val->dst_ifindexes[i];
        bpf_clone_redirect(skb, dst_ifindex, 0);
    }
}

char LICENSE[] SEC("license") = "GPL";

SEC("tc")
int tc_mirroring(struct __sk_buff *skb) {
    mirroring(skb);

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = parse_ethhdr(data, data_end);
    if(!eth)
        return 0;

    __u16 eth_type;
    void *next_header = parse_ether_type_and_next(eth, data_end, &eth_type);
    if(!next_header)
        return 0;

    if(eth_type != ETH_P_IP)
        return 0;

    struct iphdr *ip = parse_iphdr(next_header, data_end);
    if(!ip)
        return 0;

    monitor_key key = skb->ifindex;
    monitor_value *monitor_val = bpf_map_lookup_elem(&monitor_map, &key);
    if(!monitor_val || *monitor_val == 0)
        return 0;

    struct monitor_event *event = bpf_ringbuf_reserve(&monitor_ringbuf, sizeof(struct monitor_event), 0);
    if(event){
        __builtin_memcpy(event->src_mac, eth->h_source, ETH_ALEN);
        __builtin_memcpy(event->dst_mac, eth->h_dest, ETH_ALEN);
        event->eth_type = eth_type;
        event->src_ip = ip->saddr;
        event->dst_ip = ip->daddr;
        event->ip_proto = ip->protocol;

        bpf_ringbuf_submit(event, 0);
    }

    return 0; 
}