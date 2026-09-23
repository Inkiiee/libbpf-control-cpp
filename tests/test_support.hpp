#ifndef TEST_SUPPORT_HPP
#define TEST_SUPPORT_HPP

#include <initializer_list>
#include <iostream>
#include <string_view>
#include <utility>

#define TEST_CHECK(expression)                                                   \
    do{                                                                          \
        if(!(expression)){                                                       \
            std::cerr << __FILE__ << ':' << __LINE__                            \
                      << ": check failed: " #expression << '\n';               \
            return false;                                                       \
        }                                                                        \
    } while(false)

namespace test_support{
    using TestCase = std::pair<std::string_view, bool (*)()>;

    inline int run(std::initializer_list<TestCase> test_cases){
        int failure_count = 0;

        for(const auto& [name, test_case] : test_cases){
            if(test_case()){
                std::cout << "[PASS] " << name << '\n';
                continue;
            }

            std::cerr << "[FAIL] " << name << '\n';
            ++failure_count;
        }

        return failure_count == 0 ? 0 : 1;
    }
}

#endif
