# libbpf-control-cpp

C++20 utilities for managing **libbpf maps, BPF programs, Linux TC attachments, and dynamic network interfaces**.

The project provides a small C++ layer around recurring eBPF userspace lifecycle problems rather than trying to hide libbpf itself.

> **Status:** Experimental / under active development.

## Overview

`libbpf-control-cpp` is organized around five main responsibilities:

- process-wide libbpf runtime initialization
- BPF map / ring buffer / perf buffer management
- BPF object loading and existing-map FD reuse
- desired TC attachment policy management
- reconciliation between desired policy and actual kernel TC state

The current `main.cpp` and `tc_bpf/` program are **examples** showing how the utilities can be used. They are not required by the core design.

The repository also contains `TerminationSignalWaiter`, a small process-shutdown utility used by the example. It is independent of the BPF control layer.

## Architecture

```mermaid
flowchart TD
    APP[Application]

    subgraph Userspace[Userspace C++20]
        RUNTIME[libbpf Runtime\nStrict 1.0-compatible behavior]
        MAP[BPF Map Wrappers\nMap / Ring Buffer / Perf Buffer]
        LOADER[BpfProgLoader]
        PROGRAM[BpfProgram\nOwned FD / Program ID]
        ATTACHER[Attacher\nDesired Attachment Policy]
        MANAGER[BpfAttachManager\nTC Reconciliation / Retry]
        IFACE[InterfaceLoader\nDynamic NIC Monitoring]
    end

    subgraph Kernel[Linux Kernel]
        PINNED[Pinned BPF Maps]
        BPFPROG[Loaded BPF Program]
        TC[TC ingress / egress filters]
    end

    APP --> RUNTIME
    RUNTIME --> MAP
    RUNTIME --> LOADER
    RUNTIME --> MANAGER
    APP --> ATTACHER

    MAP <--> PINNED
    MAP --> LOADER
    LOADER --> PROGRAM
    PROGRAM --> BPFPROG

    ATTACHER --> MANAGER
    PROGRAM --> MANAGER
    IFACE <--> MANAGER
    MANAGER <--> TC
    TC --> BPFPROG
```

## Components

### libbpf runtime initialization

Before using libbpf directly, initialize the process-wide runtime:

```cpp
#include "bpf_runtime/bpf_runtime.hpp"

if (bpf_runtime::initialize() < 0) {
    // strict-mode initialization failed
}
```

`bpf_runtime::initialize()` enables `LIBBPF_STRICT_ALL`. This gives libbpf 0.x the clean pointer and direct-error behavior used by libbpf 1.x:

- pointer-returning constructor APIs return `nullptr` on failure
- integer-returning APIs return direct negative error codes
- current section-name and BTF map-definition rules are enforced
- old kernels receive libbpf's automatic `RLIMIT_MEMLOCK` handling when required

Initialization is performed once through a thread-safe function-local static. Calling the function repeatedly is safe.

The map wrappers, `BpfProgLoader`, and `BpfAttachManager` call it defensively on their initial libbpf entry paths. Applications that mix this project with direct libbpf calls must call `bpf_runtime::initialize()` before the first direct libbpf API call.

This ordering is a process-wide contract. Calling a direct libbpf API first and initializing afterwards is too late. Code in this project assumes strict-mode semantics, checks pointer-returning constructors against `nullptr`, and does not use `libbpf_get_error()`.

### BPF map wrappers

The map-control layer wraps common userspace operations for BPF maps and event buffers.

Available components include:

- `BpfMapControl`
- `BpfRingBufferControl`
- `BpfPerfBufferControl`

Pinned maps can be opened and reused by userspace code instead of being recreated on every process start. A map does not have to be pinned to be reused by `BpfProgLoader`; it only needs to be open and expose a valid FD.

When an existing pin is opened, its kernel layout is checked against the layout requested by the wrapper. Plain maps validate type, key size, value size, and maximum entries. Ring buffers validate their map type and byte capacity, and perf buffers validate their map type. A mismatch returns `kPinnedMapMismatchError`; the wrapper does not silently adopt the old layout.

Pin ownership is explicit:

- a wrapper owns a pin only when its own `pin()` call created it
- opening an existing pin does not transfer ownership
- `unpin()` rejects removal when the wrapper is not the owner
- `pin()` returns `kAlreadyOwnsPinError` when that wrapper already owns a pin
- `pin()` returns `kAlreadyPinnedError` when the requested target path already exists
- changing the pin path is an explicit `unpin()` followed by `pin(new_path)` operation; `pin()` never replaces the old pin automatically
- if an owned pin path is already absent, `unpin()` clears the local path/ownership state and returns `kNotPinnedError`
- if removal itself fails, `unpin()` restores local ownership and returns `kUnpinningError`
- `close()` releases the FD and local pin ownership but deliberately leaves the bpffs pin in place
- pin ownership is transferred when a wrapper is moved

Ring/perf map lifetime and userspace event-buffer lifetime are separate. `event_buffer_create()` requires the corresponding callbacks, but a missing callback or userspace-buffer creation failure does not close the already-open map FD. The caller can correct the callback/configuration and retry. `close()` destroys the userspace ring/perf buffer before closing the backing map FD.

### `BpfProgLoader`

`BpfProgLoader` loads a compiled BPF object and prepares a program for userspace ownership.

Its responsibilities include:

- opening a BPF object file
- selecting a program by function name
- assigning the BPF program type
- connecting BPF object maps to existing open map FDs with `bpf_map__reuse_fd()`
- loading the object into the kernel
- obtaining an independent program FD and program ID

`BpfProgLoader` does not pin programs. Program lifetime is managed by the duplicated FD stored in `BpfProgram` and by any kernel attachment that references the program.

Example:

```cpp
std::vector<BpfBase*> maps {
    &mirror_map,
    &monitor_map,
    &monitor_ringbuf
};

auto [program, error] = BpfProgLoader::load_program(
    "tc_mirroring.o",
    "tc_mirroring",
    maps
);

if (error != BpfProgLoaderError::kNoError) {
    // handle error
}
```

### `BpfProgram`

`BpfProgram` represents a loaded kernel BPF program.

It stores:

- duplicated program FD
- kernel program ID
- program type
- function name
- section name

The duplicated FD is released automatically when the `BpfProgram` object is destroyed.

### `Attacher`

`Attacher` describes **desired attachment state** rather than directly modifying TC state.

Supported modes:

```cpp
AttachMode::kAttachSelective
AttachMode::kAttachAll
```

Example:

```cpp
auto& manager = BpfAttachManager::get_instance();

auto attacher = manager.create_attacher(
    program,
    {
        .priority = 100,
        .handle = 1,
        .is_ingress = true
    }
);

if (!attacher) {
    // manager initialization failed, or the program handle is invalid
    return 1;
}

attacher->add_target("eth0");
attacher->add_target("eth1");
```

Policy updates are exposed to the manager through immutable snapshots.

### `BpfAttachManager`

`BpfAttachManager` reconciles the desired attachment policy with the current TC state.

The manager becomes available only after both libbpf runtime initialization and the initial interface-monitor start succeed. `create_attacher()` returns `nullptr` when manager initialization failed, when the program pointer is null, when its FD is negative, or when its program ID is zero.

It reacts to both:

- `Attacher` policy changes
- network-interface changes reported by `InterfaceLoader`

If a running `InterfaceLoader` monitor fails, its failure callback only schedules a restart request. The manager worker performs the actual cleanup and restart after `kMonitorRestartDelay` (currently 5 seconds), so the monitor thread never tries to join itself. This delay is separate from the attachment retry delay. Failed restart attempts are scheduled again using the same monitor-restart delay. A successful restart performs an initial full refresh, whose change callback schedules every attacher for reconciliation.

During destruction, the manager stops and joins its worker before stopping the interface monitor. This prevents a restart from racing with shutdown.

TC queries distinguish four states:

```cpp
enum class FilterState {
    kOurProgram,
    kOtherProgram,
    kNotFound,
    kError
};
```

This avoids treating a missing filter as an operational error.

## TC Reconciliation

```mermaid
flowchart TD
    CHANGE[Policy or NIC change]
    QUEUE[Queue ApplyRequest]
    WAIT{Immediate or retry due?}
    SNAPSHOT[Read immutable policy + NIC snapshot]
    QUERY[Query TC filter state]

    OUR{Our program?}
    WANTED{Program desired here?}
    OTHER{Other program?}
    OK[Desired state reached]
    ATTACH[Attach / replace TC filter]
    DETACH[Detach our TC filter]
    FAIL[Operation failed]
    RETRY{Retry limit reached?}
    REQUEUE[Requeue delayed request]
    GIVEUP[Report reconciliation failure]

    CHANGE --> QUEUE --> WAIT
    WAIT -->|ready| SNAPSHOT --> QUERY
    WAIT -->|not yet| WAIT

    QUERY --> OUR
    OUR -->|yes| WANTED
    OUR -->|no| OTHER

    WANTED -->|yes| OK
    WANTED -->|no| DETACH

    OTHER -->|other / missing and desired| ATTACH
    OTHER -->|other / missing and not desired| OK

    ATTACH -->|success| OK
    DETACH -->|success / already absent| OK

    ATTACH -->|failure| FAIL
    DETACH -->|failure| FAIL
    QUERY -->|query error| FAIL

    FAIL --> RETRY
    RETRY -->|no| REQUEUE --> WAIT
    RETRY -->|yes| GIVEUP
```

Apply requests are coalesced by attacher ID. A newer request replaces an older queued request for the same attacher, preventing stale retries from taking priority over a more recent policy update.

## Dynamic Interface Handling

`InterfaceLoader` maintains a snapshot of available network interfaces and monitors link/address changes.

When the interface set changes, attachment policies are scheduled for reconciliation again so that TC state can follow interface hotplug or recreation.

Snapshots are immutable and can be read concurrently without holding the refresh lock. Netlink bursts are debounced, and dropped or truncated netlink messages trigger a full interface resynchronization instead of leaving stale state behind.

`start_monitor()` accepts two optional callbacks:

```cpp
bool start_monitor(
    ChangeHandler on_change = {},
    FailureHandler on_failure = {}
);
```

- `ChangeHandler` receives the new immutable snapshot after a refresh
- `FailureHandler` receives the fatal `InterfaceError` when a running monitor exits because polling or the netlink descriptor failed
- an omitted callback is simply not invoked
- synchronous startup failures are reported by the `false` return value and `get_last_error()`, not through `FailureHandler`
- callbacks run outside loader locks and exceptions are contained and logged
- `FailureHandler` runs on the failing monitor thread; it must only notify another worker and must not directly call `start_monitor()` or `stop_monitor()`
- `start_monitor()` and `stop_monitor()` may be called from different threads, but they must never be called concurrently
- snapshot queries and `request_refresh()` may be called from any thread; when no monitor is running, `request_refresh()` refreshes synchronously on the calling thread

A fatal asynchronous failure changes the internal monitor state to failed, so `is_monitoring()` becomes `false`. A later `start_monitor()` cleans up the failed thread and descriptors before creating a new monitor. When no failure callback is installed, no external notification or automatic restart occurs.

## Termination Signal Handling

`TerminationSignalWaiter` turns `SIGINT` and `SIGTERM` into one ordinary C++ callback on a dedicated `std::jthread`.

Its construction order is part of the API contract:

- construct it before creating any other worker thread; threads inherit the creating thread's signal mask
- construct and destroy it on the same thread because POSIX signal masks are thread-local
- the constructor blocks `SIGINT`/`SIGTERM`, while `start()` only starts the waiting thread
- `pthread_sigmask()` and `start()` failures are returned as positive errno values, not through `errno` or `-1`
- the termination callback runs outside signal-handler context, may use locks/allocation/logging, and is invoked at most once
- destruction stops the waiter, drains pending termination signals, and restores the previous signal mask

## Example Code

The repository currently contains a mirroring / monitoring example:

```text
src/main.cpp

tc_bpf/
├── tc_mirroring.c
├── tc_comm.h
└── vmlinux.h
```

The example demonstrates:

- opening or creating pinned maps
- loading an unpinned BPF program with reused map FDs
- creating an `Attacher`
- attaching to selected interfaces
- ring-buffer polling
- synchronous `SIGINT` / `SIGTERM` handling through `TerminationSignalWaiter`
- simple TC mirroring / monitoring

The example-specific interface names, object paths, and map names should not be treated as library defaults.

`tc_bpf/tc_comm.h` is shared by userspace and BPF code. BPF sources must include `vmlinux.h` before `tc_comm.h`; userspace builds obtain the required kernel integer types from `linux/types.h`.

## Project Structure

```text
.
├── include/
│   ├── bpf_runtime/
│   │   └── bpf_runtime.hpp
│   │
│   ├── bpf_map_control/
│   │   ├── bpf_control_base.hpp
│   │   ├── bpf_map_control.h
│   │   ├── bpf_perf_buffer_control.h
│   │   └── bpf_ring_buffer_control.h
│   │
│   ├── bpf_tool/
│   │   ├── bpf_attach_manager.h
│   │   ├── bpf_attacher.h
│   │   ├── bpf_prog_loader.h
│   │   └── bpf_types.hpp
│   │
│   ├── nic_check/
│   │   └── interface_loader.h
│   │
│   └── utils/
│       └── termination_signal_waiter.h
│
├── src/
│   ├── bpf_map_control/
│   ├── bpf_tool/
│   ├── nic_check/
│   ├── utils/
│   └── main.cpp          # example application
│
└── tc_bpf/               # example BPF program
    ├── tc_mirroring.c
    ├── tc_comm.h
    └── vmlinux.h
```

## Requirements

- Linux
- C++20-compatible compiler
- CMake 3.16 or newer
- libbpf 0.7 or newer
- pthread
- clang with BPF target support for the included example
- kernel eBPF / TC support
- bpffs when using pinned BPF maps

The included BPF example is currently compiled with:

```text
-target bpf
-mcpu=v3
-O2
```

## Build

```bash
git clone https://github.com/Inkiiee/libbpf-control-cpp.git
cd libbpf-control-cpp

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The current CMake configuration builds the userspace example together with the sample TC BPF object.

The sample BPF object requires `clang` with BPF target support. When clang is unavailable it is skipped with a warning and only the userspace code is built; configure with `-DBUILD_BPF_EXAMPLE=OFF` to disable it explicitly.

## Yocto / Cross Compilation

The build supports the `SDKTARGETSYSROOT` environment variable commonly provided by Yocto SDK environments.

```bash
source /path/to/environment-setup-<target>

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The configured SDK target sysroot is used for userspace include/library lookup and for the sample BPF build include path.

## Reliability and Compatibility Notes

The current implementation includes the following compatibility and lifecycle behavior:

- libbpf 0.x is switched to `LIBBPF_STRICT_ALL` before wrapper-managed libbpf operations
- strict-mode pointer failures are checked as `nullptr`; the implementation does not depend on `libbpf_get_error()`
- `BpfProgLoader` reuses any valid open map FD; map pinning is optional
- programs are no longer pinned automatically
- existing pinned maps are reused only when their relevant layout matches the wrapper request
- perf-event array sizing uses `libbpf_num_possible_cpus()` so offline and hot-pluggable CPUs are accounted for
- ring/perf userspace-buffer creation failures leave their backing map open for retry
- ring and perf buffer managers release their userspace buffer objects before closing the backing map FD
- libbpf runtime initialization failures have dedicated error results
- `BpfAttachManager` rejects invalid program handles and does not start reconciliation after runtime or initial interface-monitor initialization failure
- asynchronous interface-monitor failures are reported through an optional callback and automatically restarted by `BpfAttachManager`
- map pin ownership is transferred on move and cleared on close or unpin
- `close()` clears local FD and pin state even when the underlying `close(2)` reports an error
- `TerminationSignalWaiter` restores the caller's original signal mask during destruction
- logging is serialized across threads

## Current Limitations

This project is still experimental.

Current limitations include:

- attachment reconciliation uses a bounded retry count
- persistent reconciliation failures are not retried indefinitely
- initial interface-monitor startup failure makes `BpfAttachManager` unavailable; automatic monitor restart applies only after a successful initial start
- an existing TC program at the same handle / priority may be replaced during reconciliation
- multiple attachers using the same interface, direction, handle, and priority are not conflict-resolved automatically
- the repository currently builds an example executable rather than exposing a packaged installable CMake library target
- `main.cpp` and `tc_bpf/` contain example-specific paths, interfaces, and behavior

## Design Goals

The project intentionally keeps libbpf concepts visible.

The goal is to provide reusable C++ ownership and lifecycle primitives around:

```text
BPF map lifetime
        +
optional map pinning and FD reuse
        +
BPF program lifetime
        +
TC desired state
        +
network interface changes
        +
retry / reconciliation
```

It is intended as a lightweight utility layer, not as a replacement for libbpf.

## License

This project is licensed under the [MIT License](LICENSE).

Third-party dependencies, including libbpf and Linux/kernel headers or generated artifacts, remain subject to their respective upstream licenses.
