function(add_bpf_control_unit_test target source)
    add_executable(${target} ${source})

    target_link_libraries(${target} PRIVATE
        bpf_control::core
    )

    target_compile_options(${target} PRIVATE
        -Wall
        -Wextra
        -Wshadow
    )

    target_compile_definitions(${target} PRIVATE
        _GLIBCXX_ASSERTIONS
    )

    add_test(NAME ${target} COMMAND ${target})
    set_tests_properties(${target} PROPERTIES
        LABELS unit
        TIMEOUT 10
    )
endfunction()

add_bpf_control_unit_test(bpf_attacher_test bpf_attacher_test.cpp)
add_bpf_control_unit_test(bpf_program_test bpf_program_test.cpp)
add_bpf_control_unit_test(termination_signal_waiter_test termination_signal_waiter_test.cpp)
