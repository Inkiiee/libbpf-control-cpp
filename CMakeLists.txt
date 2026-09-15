cmake_minimum_required(VERSION 3.16)

# SDKTARGETSYSROOT 환경변수 지원 (Yocto SDK 크로스 컴파일)
# CMAKE_SYSROOT는 project() 전에 설정해야 컴파일러에 반영됨
if(DEFINED ENV{SDKTARGETSYSROOT})
    set(SDKTARGETSYSROOT $ENV{SDKTARGETSYSROOT})
    set(CMAKE_SYSROOT ${SDKTARGETSYSROOT})
    set(CMAKE_FIND_ROOT_PATH ${SDKTARGETSYSROOT})
else()
    set(SDKTARGETSYSROOT "" CACHE PATH "Yocto SDK target sysroot path")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(bpf_control C CXX)

# std::jthread / std::stop_token 은 pthread 를 요구한다.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(SRCS
    src/main.cpp
    src/bpf_map_control/bpf_map_control.cpp
    src/bpf_map_control/bpf_ring_buffer_control.cpp
    src/bpf_map_control/bpf_perf_buffer_control.cpp
    src/nic_check/interface_loader.cpp
    src/utils/safe_command.cpp
    src/utils/bpf_prog_loader.cpp
)

add_executable(bpf_control ${SRCS})

target_compile_options(bpf_control PRIVATE
    -Wall
    -Wextra
    -Wshadow
    $<$<CONFIG:Release>:-O2>
)

# 인클루드 경로
target_include_directories(bpf_control PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpf_map_control
)
target_include_directories(bpf_control SYSTEM PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/asio_1.38.0/include
)

target_compile_definitions(bpf_control PRIVATE
    ASIO_STANDALONE
    _GLIBCXX_ASSERTIONS
)

target_link_libraries(bpf_control PRIVATE
    bpf
    Threads::Threads
)

if(SDKTARGETSYSROOT)
    target_include_directories(bpf_control PRIVATE
        ${SDKTARGETSYSROOT}/usr/include
    )
    target_link_directories(bpf_control PRIVATE
        ${SDKTARGETSYSROOT}/usr/lib
    )
endif()

add_subdirectory(tc_bpf)