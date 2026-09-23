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

# BPF 예제는 clang 의 BPF 타겟을 요구한다. 유저스페이스 코드만 빌드하려면 OFF.
option(BUILD_BPF_EXAMPLE "Build the example TC BPF object (requires clang with BPF target support)" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(bpf_control C CXX)

# std::jthread / std::stop_token 은 pthread 를 요구한다.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(BPF_CONTROL_CORE_SRCS
    src/bpf_map_control/bpf_map_control.cpp
    src/bpf_map_control/bpf_ring_buffer_control.cpp
    src/bpf_map_control/bpf_perf_buffer_control.cpp
    src/nic_check/interface_loader.cpp
    src/bpf_tool/bpf_attach_manager.cpp
    src/bpf_tool/bpf_attacher.cpp
    src/bpf_tool/bpf_prog_loader.cpp
    src/utils/termination_signal_waiter.cpp
)

add_library(bpf_control_core STATIC ${BPF_CONTROL_CORE_SRCS})

add_library(bpf_control::core ALIAS bpf_control_core)

target_compile_options(bpf_control_core PRIVATE
    -Wall
    -Wextra
    -Wshadow
    $<$<CONFIG:Release>:-O2>
)

# 인클루드 경로
target_include_directories(bpf_control_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpf_map_control
)

target_compile_definitions(bpf_control_core PRIVATE
    _GLIBCXX_ASSERTIONS
)

target_link_libraries(bpf_control_core PUBLIC
    bpf
    Threads::Threads
)

if(SDKTARGETSYSROOT)
    target_include_directories(bpf_control_core PUBLIC
        ${SDKTARGETSYSROOT}/usr/include
    )
    target_link_directories(bpf_control_core PUBLIC
        ${SDKTARGETSYSROOT}/usr/lib
    )
endif()

add_executable(bpf_control src/main.cpp)

target_include_directories(bpf_control PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(bpf_control PRIVATE
    -Wall
    -Wextra
    -Wshadow
    $<$<CONFIG:Release>:-O2>
)

target_compile_definitions(bpf_control PRIVATE
    _GLIBCXX_ASSERTIONS
)

target_link_libraries(bpf_control PRIVATE
    bpf_control::core
)

include(CTest)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

if(BUILD_BPF_EXAMPLE)
    add_subdirectory(tc_bpf)
endif()
