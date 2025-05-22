#ifndef CONFIG_H
#define CONFIG_H

// Should be consistent with the host system's MAX_PIDS
#define MAX_PIDS 4194304

// Enable or disable the recorder/tracker module
#define ENABLE_RECORDER
#define ENABLE_TRACKER

// Enables tracing only for the specified TARGET_COMM process and its children
#define PARTIAL_TRACE
#ifdef PARTIAL_TRACE
// Process name to trace when partial tracing is enabled
#define TARGET_COMM "bash" 
#define TARGET_COMM_LEN (sizeof(TARGET_COMM) - 1)
#else
// Full tracing just ignore backtrack itself
#define IGNORE_COMM "backtrack" 
#define IGNORE_COMM_LEN ((__u32)sizeof(IGNORE_COMM) - 1)
#endif //PARTIAL_TRACE

// Size of the ring buffer in bytes
#define RINGBUF_SIZE 512 * 1024 * 1024
// Number of worker threads
#define WORKER_COUNT 4
// Size of each worker's event queue
#define WORKER_QUEUE_SIZE 262144 // (256*1024)

// Output file paths for tracker and recorder logs
#define TRACKER_LOG_PATH "./log_tracker.txt"
#define RECORDER_LOG_PATH "./log_recorder.txt"

// Enable capturing of specific syscalls
#define CAPTURE_ACCEPT
#define CAPTURE_ACCEPT4
#define CAPTURE_BIND
#define CAPTURE_CHDIR
#define CAPTURE_CHMOD
#define CAPTURE_CLONE
#define CAPTURE_CLONE3
#define CAPTURE_CLOSE
#define CAPTURE_CONNECT
#define CAPTURE_CREAT
#define CAPTURE_DUP
#define CAPTURE_DUP2
#define CAPTURE_DUP3
#define CAPTURE_EXECVE
#define CAPTURE_EXIT
#define CAPTURE_EXIT_GROUP
#define CAPTURE_FCHDIR
#define CAPTURE_FCHMOD
// #define CAPTURE_FCHMODAT // TODO: tracing disabled due to BPF link failed with -13(Permission denied); cause unknown.
#define CAPTURE_FCNTL
#define CAPTURE_FTRUNCATE
#define CAPTURE_LISTEN
#define CAPTURE_MMAP
#define CAPTURE_MPROTECT
#define CAPTURE_MQ_GETSETATTR
#define CAPTURE_MQ_NOTIFY
#define CAPTURE_MQ_OPEN
#define CAPTURE_MQ_TIMEDRECEIVE
#define CAPTURE_MQ_TIMEDSEND
#define CAPTURE_MQ_UNLINK
#define CAPTURE_MSGCTL
#define CAPTURE_MSGGET
#define CAPTURE_MSGRCV
#define CAPTURE_MSGSND
#define CAPTURE_MUNMAP
#define CAPTURE_NEWFSTATAT
#define CAPTURE_OPEN
#define CAPTURE_OPENAT
#define CAPTURE_PIPE
#define CAPTURE_PIPE2
#define CAPTURE_PREAD64
#define CAPTURE_PREADV
#define CAPTURE_PREADV2
#define CAPTURE_PTRACE
#define CAPTURE_PWRITE64
#define CAPTURE_PWRITEV
#define CAPTURE_PWRITEV2
#define CAPTURE_READ
#define CAPTURE_READV
#define CAPTURE_RECVFROM
#define CAPTURE_RECVMMSG
#define CAPTURE_RECVMSG
#define CAPTURE_RENAME
#define CAPTURE_RENAMEAT
#define CAPTURE_RENAMEAT2
#define CAPTURE_SENDMMSG
#define CAPTURE_SENDMSG
#define CAPTURE_SENDTO
#define CAPTURE_SHMAT
#define CAPTURE_SHMCTL
// #define CAPTURE_SHMDT // TODO: tracing disabled due to BPF link failed with -13(Permission denied); cause unknown.
#define CAPTURE_SHMGET
#define CAPTURE_SOCKET
#define CAPTURE_STATX
#define CAPTURE_TRUNCATE
#define CAPTURE_UNLINK
#define CAPTURE_UNLINKAT
#define CAPTURE_WRITE
#define CAPTURE_WRITEV
// #define CAPTURE_STAT // stat/lstat/fstat appear to be routed through newfstatat(); no separate tracepoints exist.
// #define CAPTURE_FSTAT
// #define CAPTURE_LSTAT

#endif //CONFIG_H