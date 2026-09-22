project(tc_bpf C)

# BPF 프로그램은 clang으로 직접 컴파일해야 하므로 custom command 사용.
# clang 이 없다고 해서 전체 configure 를 실패시키지는 않는다. 이 디렉터리는
# 예제일 뿐이고, 유저스페이스 라이브러리는 clang 없이도 빌드되어야 한다.
find_program(CLANG clang)
if(NOT CLANG)
    message(WARNING
        "clang not found: skipping the example BPF object (tc_mirroring.o). "
        "Install clang with BPF target support, or configure with "
        "-DBUILD_BPF_EXAMPLE=OFF to silence this warning.")
    return()
endif()

set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/tc_mirroring.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/tc_mirroring.o)
set(BPF_DEPFILE ${BPF_OBJ}.d)

# libbpf 의 bpf_tracing.h 가 대상 커널의 레지스터 규칙을 고를 때 쓰는 매크로다.
# libbpf 가 인식하는 이름: x86, arm, arm64, s390, mips, powerpc, sparc, riscv,
# arc, loongarch. 이 예제의 기본 타깃은 Yocto armv8a SDK 이므로 arm64 다.
set(BPF_ARCH "arm64" CACHE STRING "Target architecture for libbpf tracing macros")

# __aarch64__, __LP64__ 같은 컴파일러·ABI 매크로는 직접 정의하지 않는다.
# 실제 대상과 다른 헤더 경로나 자료형 조건이 선택될 수 있고, __LP64__ 는
# -target bpf 에서 clang 이 이미 정의한다. 헤더를 못 찾는 경우(예: asm/types.h)
# 는 매크로를 덧붙이지 말고 아래 BPF_INCLUDES 에 올바른 sysroot 경로를 준다.
#
# -mcpu 는 최적화 옵션이 아니라 clang 이 생성할 BPF 명령어 집합을 정한다.
# 대상 커널이 이 ISA 레벨을 지원하는지는 실제 프로그램 로드로 확인해야 한다.
set(BPF_CFLAGS
    -g -O2
    -target bpf
    -mcpu=v3
    -D__TARGET_ARCH_${BPF_ARCH}
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

# vmlinux.h 나 프로젝트 include/ 의 헤더를 고쳐도 다시 빌드되도록 clang depfile
# 을 쓴다. DEPFILE 은 Makefile·Ninja generator 에서만 지원하고, 절대 경로 해석은
# CMP0116(CMake 3.20) 기준을 따른다. 그 밖의 환경에서는 아래 DEPENDS 목록만으로
# 동작하므로 헤더 변경은 수동 재빌드가 필요하다.
set(BPF_DEPFILE_OPT "")
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.20 AND CMAKE_GENERATOR MATCHES "Make|Ninja")
    set(BPF_DEPFILE_OPT DEPFILE ${BPF_DEPFILE})
else()
    message(STATUS
        "tc_bpf: DEPFILE unsupported with this generator/CMake version; "
        "header changes may require a manual rebuild of tc_mirroring.o")
endif()

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG} ${BPF_CFLAGS} ${BPF_INCLUDES}
            -MMD -MP -MF ${BPF_DEPFILE}
            -c ${BPF_SRC} -o ${BPF_OBJ}
    ${BPF_DEPFILE_OPT}
    DEPENDS ${BPF_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/tc_comm.h
    COMMENT "Compiling BPF program: tc_mirroring.c -> tc_mirroring.o"
    COMMAND_EXPAND_LISTS
    VERBATIM
)

add_custom_target(tc_mirroring ALL DEPENDS ${BPF_OBJ})
