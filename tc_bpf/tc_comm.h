/*
Class Name   : tc_comm.h
@version     : 1.0
@author      : Inkiiee
@modify      : 2026-09-07, 프로그램 작성
*/

#ifndef TC_COMM_H
#define TC_COMM_H

#define MIRRORING_MAX_INSTANCES 10
#define MONITORING_MAX_INSTANCES 10
#define MONITOR_RINGBUF_SIZE (16*1024*1024u) // 16MB ring buffer size

typedef __u32 monitor_key; // 모니터링 맵의 키 타입 (예: ifindex)
typedef __u32 monitor_value; // 모니터링 맵의 값 타입 (예: 0: 비활성화, 1: 활성화)

typedef __u32 mirror_key; // 미러링 맵의 키 타입 (예: ifindex)
struct mirror_value {
    __u32 dst_ifindexes[MIRRORING_MAX_INSTANCES]; // 미러링한 패킷을 전달할 인터페이스의 ifindex 배열
    __u32 enabled; // 미러링 활성화 여부 (1: 활성화, 0: 비활성화)
    __u32 dst_ifindex_count; // dst_ifindexes 배열에 저장된 ifindex의 개수
} __attribute__((packed, aligned(4))); // 구조체를 패킹하여 메모리 정렬을 방지

struct monitor_event {
    __u8 src_mac[6]; // 모니터링한 패킷의 출발지 MAC 주소
    __u8 dst_mac[6]; // 모니터링한 패킷의 목적지 MAC 주소
    __u16 eth_type; // 모니터링한 패킷의 Ethernet 타입
    __u32 src_ip; // 모니터링한 패킷의 출발지 IP 주소 (IPv4)
    __u32 dst_ip; // 모니터링한 패킷의 목적지 IP 주소 (IPv4)
    __u8 ip_proto; // 모니터링한 패킷의 IP 프로토콜 번호
} __attribute__((packed, aligned(4))); // 구조체를 패킹하여 메모리 정렬을 방지



#endif // TC_COMM_H