/*
Class Name   : bpf_map_control.h
@version     : 1.1
@author      : Inkiiee
@modify      : 2026-09-07, 프로그램 작성
               2026-09-14, pin되어있는 맵을 사용할 때, 정보를 가져오는 load_map_info 함수 추가
*/

#ifndef BPF_MAP_CONTROL_H
#define BPF_MAP_CONTROL_H

#include "bpf_control_base.hpp"

namespace bpf_control{
    class BpfMapControl : public BpfBase {
    public:
        BpfMapControl() = delete;
        BpfMapControl(const BpfMapControl&) = delete;
        BpfMapControl& operator=(const BpfMapControl&) = delete;
        
        BpfMapControl(BpfMapControl&&) = default;
        BpfMapControl& operator=(BpfMapControl&&) = default;
        BpfMapControl(const std::string& name, std::size_t key_sz, std::size_t value_sz, std::size_t max_ent, bpf_map_type map_type = BPF_MAP_TYPE_HASH);

        virtual BpfControlErrorCode open(bool is_pinned = false, const std::string& pin_path = "") override;
        BpfControlErrorCode update(const void* key, const void* value, std::uint64_t flags = BPF_ANY); //ex: std::map<key_type, value_type>::insert_or_assign(key, value)
        BpfControlErrorCode lookup(const void* key, void* value); // ex: std::map<key_type, value_type>::find(key)
        BpfControlErrorCode delete_entry(const void* key); // ex: std::map<key_type, value_type>::erase(key)
        BpfControlErrorCode clear(); //ex: std::map<key_type, value_type>::clear()
        BpfControlErrorCode get_next_key(const void* key, void* next_key); // eBPF맵은 기본적으로 키를 모두 가져오는 기능이 없어서 하나씩 순회하는구조

        std::size_t get_key_size() const { return key_size_; } // 키의 데이터 크기
        std::size_t get_value_size() const { return value_size_; } // 값의 데이터 크기
        std::size_t get_max_entries() const { return max_entries_; } // 맵에 저장할 수 있는 최대 엔트리 수
        bpf_map_type get_map_type() const { return map_type_; } // 맵의 타입(주로 BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_LRU_HASH를 사용함)
    private:
        std::size_t key_size_; // 키의 데이터 크기
        std::size_t value_size_; // 값의 데이터 크기
        std::size_t max_entries_; // 맵에 저장할 수 있는 최대 엔트리 수
        bpf_map_type map_type_; // eBPF 맵의 타입(해쉬 맵인지, 선형큐 형태의 해쉬맵인지 등)

        BpfControlErrorCode load_map_info();
    };
}

#endif // BPF_MAP_CONTROL_H