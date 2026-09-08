project(tc_bpf C)

# BPF 프로그램은 clang으로 직접 컴파일해야 하므로 custom command 사용
find_program(CLANG clang REQUIRED)

set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/tc_mirroring.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/tc_mirroring.o)

set(BPF_CFLAGS
    -g -O2
    -target bpf
    -mcpu=v3
    -D__aarch64__
    -D__LP64__
    -D__BPF__
)

set(BPF_INCLUDES
    -I${CMAKE_CURRENT_SOURCE_DIR}
    -I${CMAKE_SOURCE_DIR}/include
)

if(SDKTARGETSYSROOT)
    list(APPEND BPF_INCLUDES -I${SDKTARGETSYSROOT}/usr/include)
endif()

if(CMAKE_C_COMPILER_ARG1 MATCHES "--sysroot=([^ ]+)")
    list(APPEND BPF_INCLUDES -I${CMAKE_MATCH_1}/usr/include)
endif()

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG} ${BPF_CFLAGS} -c ${BPF_SRC} -o ${BPF_OBJ} ${BPF_INCLUDES}
    DEPENDS ${BPF_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/tc_comm.h
    COMMENT "Compiling BPF program: tc_mirroring.c -> tc_mirroring.o"
    VERBATIM
)

add_custom_target(tc_mirroring ALL DEPENDS ${BPF_OBJ})