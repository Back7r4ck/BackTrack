# BackTrack

BackTrack is a runtime syscall audit logger for Linux, powered by eBPF. It continuously tracks key kernel entities (processes, file descriptors, sockets and more) and captures system events together with the necessary context for interpreting them.

BackTrack outputs self-contained, provenance-ready logs directly: each event is enriched with runtime-resolved identifiers and relationships, so no post-processing or log correlation is required. These logs can be used as they are to construct high-fidelity provenance graphs for attack analysis, behavioural tracing or forensic auditing.

BackTrack requires no kernel patches or external dependencies and is optimised for high-throughput workloads.

## QUICK START

#### 1. Install Dependencies

**On Ubuntu:**

```
sudo apt-get update
sudo apt-get install libelf-dev clang llvm libc6-dev-i386
```

**On Arch Linux:**

```
sudo pacman -S --needed base_devel clang elfutils zlib linux_tools lib32-glibc
```

#### 2. Build BackTrack

```
cd backtrack
make
```

#### 3. Run BackTrack

```
sudo ./backtrack
```

By default, logs are written to the current working directory when BackTrack is launched. You can change the output path and other settings in the config.h file before building.

BackTrack is tested on Ubuntu 20.04 with unmodified Linux kernel 5.15.0-50 and Archlinux with unmodified Linux kernel 6.14.4.

## Configuration

All BackTrack settings are controlled via preprocessor macros in the `backtrack\config.h` file. 

Each configuration option is documented with comments inside `backtrack\config.h`. To apply changes, run:

```
make clean
make
```

This ensures the updated configuration is reflected in the final binary.

## Log Format

BackTrack generates two types of logs: raw syscall logs and tracker logs. Both are written in JSON format, and their output paths or availability can be configured via `backtrack\config.h`.

#### Raw syscall logs

Raw syscall logs capture the exact system call events as seen by the kernel, including arguments, metadata, and return values. This format is useful for low-level inspection and debugging.

```json
{"Timestamp":1746787902665785,"EventName":"EXECVE", "SyscallID":"59", "ProcessName":"sed", "ProcessID":31136, "ThreadID":31136, "ProcessType":"process", "ReturnValue":0, "Arguments":{"Pathname":"/usr/bin/sed"}}
{"Timestamp":1746787902665870,"EventName":"OPEN_FILE", "SyscallID":"257", "ProcessName":"sed", "ProcessID":31136, "ThreadID":31136, "ProcessType":"process", "ReturnValue":3, "Arguments":{"DirFD":-100, "Pathname":"/etc/ld.so.cache", "Flags":"O_RDONLY O_CLOEXEC ", "Mode":0}}
```

#### Tracker logs

Tracker logs represent a context-resolved view of system activity. Syscalls are translated into nodes and edges that capture the control flow and data flow of the system—such as process execution, file access, and inter-process communication. These logs preserve temporal and causal relationships, and can be directly used to construct provenance graphs for security analysis or forensic reconstruction.

```json
{"LogType":"node","UUID":"037bd59b-64aa-d2b5-3d58-000000031136", "NodeName":"sed", "NodeType":"process", "ProcessID":31136, "ThreadID":31136}
{"LogType":"edge","Timestamp":1746787902665785,"FromUUID":"1bb3841d-a63c-cb93-f614-a42f073c1e03", "ToUUID":"037bd59b-64aa-d2b5-3d58-000000031136", "EventName":"EXECVE", "SyscallID":59, "FromName":"/usr/bin/sed"}
{"LogType":"edge","Timestamp":1746787902665870,"FromUUID":"16ca12a1-7a3b-e34f-6699-f25275139009", "ToUUID":"037bd59b-64aa-d2b5-3d58-000000031136", "EventName":"OPEN", "SyscallID":257, "FromName":"/etc/ld.so.cache"}
```

## More Details

For advanced usage, system architecture, and integration guidance, please refer to the [developer documentation](./developer_documentation.md).

## Acknowledgments

BackTrack draws inspiration and technical guidance from several open-source projects. In particular, we acknowledge:

- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) for providing a clean and modern foundation for building eBPF applications.

- [Kellect](https://github.com/acising/KellectAgent-Linux) for its design insights into efficient syscall monitoring and kernel-user event pipelines.

We thank the authors and maintainers of these projects for their contributions to the community.
