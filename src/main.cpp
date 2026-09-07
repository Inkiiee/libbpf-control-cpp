#include <iostream>
#include <string>

#include "bpf_map_control.h"

bool show_log_if_not_no_error(bpf_control::BpfControlErrorCode error_code){
    if(error_code != bpf_control::BpfControlErrorCode::kNoError){
        std::string error_message = std::string(bpf_control::bpf_control_error_string(error_code));
        bpf_control::log(error_message);
        return true;
    }
    return false;
}

int main(){
    // BPF map control 객체 생성
    bpf_control::BpfMapControl map_control("my_map", sizeof(int), sizeof(int), 1024);
    auto error = map_control.open(); // BPF map 열기
    if(show_log_if_not_no_error(error)) return -1;

    for(std::size_t i=0; i < map_control.get_max_entries(); ++i){
        int key = i;
        int value = i * 10;
        error = map_control.update(&key, &value); // BPF map에 값 업데이트
        if(show_log_if_not_no_error(error)) return -1;
    }

    for(std::size_t i=0; i < map_control.get_max_entries(); ++i){
        int key = i;
        int value;
        error = map_control.lookup(&key, &value); // BPF map에서 값 조회
        if(show_log_if_not_no_error(error)) return -1;
        
        std::cout << "Key: " << key << ", Value: " << value << std::endl;
    }

    error = map_control.close(); // BPF map 닫기
    if(show_log_if_not_no_error(error)) return -1;

    return 0;
}