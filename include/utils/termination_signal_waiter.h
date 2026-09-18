/*
Class Name   : termination_signal_waiter.h
@version     : 1.1
@author      : Inkiiee
@modify      : 2026-09-18, 프로그램 작성
               2026-09-18, 시그널 마스크를 생성자로 이동, 핸들러 예외 격리,
                           마스크 복원 전 pending 시그널 배출
*/

#ifndef TERMINATION_SIGNAL_WAITER_H
#define TERMINATION_SIGNAL_WAITER_H

#include <functional>
#include <signal.h>
#include <stop_token>
#include <thread>

namespace utils{
    /*
        SIGINT / SIGTERM 을 전용 스레드에서 동기적으로 받아 종료를 알린다.

        중요: 이 객체는 다른 스레드를 만들기 전에 생성해야 한다.
        pthread_sigmask 는 스레드별 속성이고, 새 스레드는 자신을 만든 스레드의
        마스크를 물려받는다. 먼저 뜬 스레드는 시그널을 막지 않은 상태라
        커널이 그쪽으로 시그널을 전달하고, 프로세스는 기본 동작으로 즉시 죽는다.
        graceful shutdown 이 통째로 사라지는데 재현은 간헐적이라 찾기 어렵다.
        그래서 마스크는 start() 가 아니라 생성자에서 건다. 생성 위치가 곧 계약이다.

        생성자는 실패할 수 있다. is_valid() / last_error() 로 확인하면 되고,
        확인을 건너뛰어도 start() 가 같은 errno 를 돌려준다.

        생성과 소멸은 같은 스레드에서 해야 한다. 마스크 복원이 스레드별이라
        다른 스레드에서 소멸하면 엉뚱한 스레드의 마스크를 푼다.

        핸들러는 시그널 핸들러 컨텍스트가 아니라 일반 스레드에서 불린다.
        async-signal-safe 제약이 없으므로 mutex, 할당, 로깅 전부 써도 된다.
        단 한 번만 호출되며, 호출 후 대기 스레드는 종료한다.
    */
    class TerminationSignalWaiter{
    public:
        using TerminationHandler = std::function<void()>;

        explicit TerminationSignalWaiter(TerminationHandler termination_handler);
        ~TerminationSignalWaiter();

        TerminationSignalWaiter(const TerminationSignalWaiter&) = delete;
        TerminationSignalWaiter& operator=(const TerminationSignalWaiter&) = delete;
        TerminationSignalWaiter(TerminationSignalWaiter&&) = delete;
        TerminationSignalWaiter& operator=(TerminationSignalWaiter&&) = delete;

        // 생성자에서 시그널 마스크를 거는 데 성공했는지 여부.
        bool is_valid() const { return is_masked_; }
        // 생성자의 pthread_sigmask 결과. 성공이면 0, 실패면 양수 errno.
        int last_error() const { return mask_error_; }

        // 대기 스레드를 띄운다. 성공이면 0, 실패면 양수 errno 를 반환한다.
        //   EALREADY : 이미 start() 되었음
        //   EINVAL   : 핸들러가 비어 있음
        //   그 외    : 생성자의 마스크 실패 errno, 또는 스레드 생성 실패
        int start();
        // 대기 스레드를 멈추고 합류한다. 마스크 복원은 소멸자가 담당한다.
        void stop();

    private:
        void wait_loop(std::stop_token stop);
        void invoke_handler();
        int restore_signal_mask();

        sigset_t termination_signals_{};
        sigset_t previous_mask_{};
        TerminationHandler termination_handler_;
        std::jthread wait_thread_;
        bool is_masked_{false};
        int mask_error_{0};
    };
}

#endif // TERMINATION_SIGNAL_WAITER_H
