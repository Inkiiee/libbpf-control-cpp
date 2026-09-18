/*
Class Name   : termination_signal_waiter.cpp
@version     : 1.1
@author      : Inkiiee
@modify      : 2026-09-18, 프로그램 작성
               2026-09-18, 시그널 마스크를 생성자로 이동, 핸들러 예외 격리,
                           마스크 복원 전 pending 시그널 배출
*/

#include "utils/termination_signal_waiter.h"

#include <cerrno>
#include <exception>
#include <string>
#include <system_error>
#include <utility>

#include <pthread.h>

#include "utils/logger.hpp"

using namespace std;

namespace{
    // 종료 지연의 상한이기도 하다. stop() 요청은 다음 타임아웃에서 확인된다.
    constexpr long kSignalWaitTimeoutNanoseconds = 200'000'000L;
}

namespace utils{
    TerminationSignalWaiter::TerminationSignalWaiter(TerminationHandler termination_handler)
        : termination_handler_(std::move(termination_handler))
    {
        ::sigemptyset(&termination_signals_);
        ::sigaddset(&termination_signals_, SIGINT);
        ::sigaddset(&termination_signals_, SIGTERM);

        // 마스크는 start() 가 아니라 여기서 건다. 이 객체보다 나중에 만들어진
        // 스레드만 마스크를 물려받으므로, 생성 시점이 그대로 계약이 된다.
        // pthread_sigmask 는 -1 이 아니라 양수 errno 를 직접 반환한다.
        const int mask_error = ::pthread_sigmask(
            SIG_BLOCK, &termination_signals_, &previous_mask_);
        if(mask_error != 0){
            mask_error_ = mask_error;
            error_code ec(mask_error, generic_category());
            utils::log("signal mask block failed: " + ec.message());
            return;
        }

        is_masked_ = true;
    }

    TerminationSignalWaiter::~TerminationSignalWaiter(){
        stop();

        const int restore_error = restore_signal_mask();
        if(restore_error != 0){
            error_code ec(restore_error, generic_category());
            utils::log("signal mask restore failed: " + ec.message());
        }
    }

    int TerminationSignalWaiter::start(){
        if(mask_error_ != 0) return mask_error_;
        if(!termination_handler_) return EINVAL;
        if(wait_thread_.joinable()) return EALREADY;

        try{
            wait_thread_ = jthread([this](stop_token stop){ wait_loop(stop); });
        } catch(const system_error& error){
            // 마스크는 소멸자가 되돌리므로 여기서 건드리지 않는다.
            const int thread_error = error.code().value();
            return thread_error == 0 ? EAGAIN : thread_error;
        }

        return 0;
    }

    void TerminationSignalWaiter::stop(){
        if(!wait_thread_.joinable()) return;

        wait_thread_.request_stop();
        wait_thread_.join();
    }

    void TerminationSignalWaiter::wait_loop(stop_token stop){
        while(!stop.stop_requested()){
            timespec timeout{};
            timeout.tv_nsec = kSignalWaitTimeoutNanoseconds;

            const int received_signal = ::sigtimedwait(
                &termination_signals_, nullptr, &timeout);
            if(received_signal == SIGINT || received_signal == SIGTERM){
                utils::log("SIGINT or SIGTERM received");
                invoke_handler();
                return;
            }

            if(received_signal == -1){
                const int error_number = errno;
                if(error_number == EAGAIN || error_number == EINTR) continue;

                error_code ec(error_number, generic_category());
                utils::log("wait signals failed: " + ec.message());
                invoke_handler();
                return;
            }
        }
    }

    // 핸들러는 jthread 안에서 호출된다. 예외가 새어나가면 그대로 std::terminate 다.
    // 안전한 종료를 담당하는 쪽이 종료 처리 때문에 죽으면 안 되므로 여기서 막는다.
    void TerminationSignalWaiter::invoke_handler(){
        try{
            termination_handler_();
        } catch(const exception& e){
            utils::log(string("termination handler threw: ") + e.what());
        } catch(...){
            utils::log("termination handler threw an unknown exception");
        }
    }

    int TerminationSignalWaiter::restore_signal_mask(){
        if(!is_masked_) return 0;

        // 복원 직전에 pending 을 비운다. 막혀 있던 시그널이 남아 있으면
        // unblock 되는 순간 배달되어 기본 동작으로 프로세스가 죽는다
        // (Ctrl+C 를 두 번 누른 경우). 대기 스레드도 이미 끝나 전달할
        // 곳이 없으므로 버린다.
        //
        // 마스크 자체는 반드시 되돌린다. 안 그러면 이 객체가 main 전체를
        // 살지 않는 경우 프로그램이 영영 시그널을 못 받고, 마스크는
        // execve() 를 넘어 상속되므로 자식 프로세스까지 물든다.
        timespec no_wait{};
        for(;;){
            if(::sigtimedwait(&termination_signals_, nullptr, &no_wait) >= 0) continue;
            if(errno == EINTR) continue;   // set 밖의 시그널에 끼였다
            break;                         // EAGAIN: 더 없다
        }

        const int mask_error = ::pthread_sigmask(
            SIG_SETMASK, &previous_mask_, nullptr);
        if(mask_error != 0)
            return mask_error;

        is_masked_ = false;
        return 0;
    }
}
