#include "test_support.hpp"

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <functional>
#include <mutex>

#include <pthread.h>
#include <unistd.h>

#include "utils/termination_signal_waiter.h"

using namespace std;
using namespace std::chrono_literals;
using namespace utils;

namespace{
    bool signal_membership_matches(const sigset_t& left, const sigset_t& right, int signal){
        return ::sigismember(&left, signal) == ::sigismember(&right, signal);
    }

    bool blocks_and_restores_termination_signals(){
        sigset_t mask_before{};
        TEST_CHECK(::pthread_sigmask(SIG_SETMASK, nullptr, &mask_before) == 0);

        {
            TerminationSignalWaiter waiter{[](){}};
            TEST_CHECK(waiter.is_valid());
            TEST_CHECK(waiter.last_error() == 0);

            sigset_t mask_while_alive{};
            TEST_CHECK(::pthread_sigmask(SIG_SETMASK, nullptr, &mask_while_alive) == 0);
            TEST_CHECK(::sigismember(&mask_while_alive, SIGINT) == 1);
            TEST_CHECK(::sigismember(&mask_while_alive, SIGTERM) == 1);
        }

        sigset_t mask_after{};
        TEST_CHECK(::pthread_sigmask(SIG_SETMASK, nullptr, &mask_after) == 0);
        TEST_CHECK(signal_membership_matches(mask_before, mask_after, SIGINT));
        TEST_CHECK(signal_membership_matches(mask_before, mask_after, SIGTERM));

        return true;
    }

    bool rejects_an_empty_handler(){
        TerminationSignalWaiter waiter{TerminationSignalWaiter::TerminationHandler{}};

        TEST_CHECK(waiter.is_valid());
        TEST_CHECK(waiter.start() == EINVAL);

        return true;
    }

    bool rejects_a_second_start(){
        TerminationSignalWaiter waiter{[](){}};

        TEST_CHECK(waiter.start() == 0);
        TEST_CHECK(waiter.start() == EALREADY);
        waiter.stop();

        return true;
    }

    bool receives_sigterm_once(){
        mutex callback_mutex;
        condition_variable callback_condition;
        int callback_count = 0;

        TerminationSignalWaiter waiter{[&](){
            {
                lock_guard<mutex> lock(callback_mutex);
                ++callback_count;
            }
            callback_condition.notify_one();
        }};

        TEST_CHECK(waiter.start() == 0);
        TEST_CHECK(::kill(::getpid(), SIGTERM) == 0);

        unique_lock<mutex> lock(callback_mutex);
        const bool callback_received = callback_condition.wait_for(
            lock,
            2s,
            [&](){ return callback_count == 1; }
        );
        lock.unlock();

        waiter.stop();

        TEST_CHECK(callback_received);
        TEST_CHECK(callback_count == 1);

        return true;
    }
}

int main(){
    return test_support::run({
        {"blocks and restores termination signals", blocks_and_restores_termination_signals},
        {"rejects an empty handler", rejects_an_empty_handler},
        {"rejects a second start", rejects_a_second_start},
        {"receives SIGTERM once", receives_sigterm_once}
    });
}
