#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/ptrace.h>
#include <mqueue.h>
#include "syscall_event.h"
#include "tracker.h"
#include "recorder.h"
#include "config.h"

FILE *output_file;
#define  BUFFER_SIZE 1024*1024

void sockaddr_to_string(const struct sockaddr *addr, char *output, size_t len) {
    if (!addr || !output || len == 0) {
        snprintf(output, len, "Invalid input");
        return;
    }

    switch (addr->sa_family) {
    case AF_INET: {
        // IPv4 address
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr_in->sin_addr, ip, sizeof(ip))) {
            snprintf(output, len, "%s:%d", ip, ntohs(addr_in->sin_port));
        } else {
            snprintf(output, len, "Invalid IPv4 address");
        }
        break;
    }
    case AF_INET6: {
        // IPv6 address
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        char ip[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip, sizeof(ip))) {
            snprintf(output, len, "[%s]:%d", ip, ntohs(addr_in6->sin6_port));
        } else {
            snprintf(output, len, "Invalid IPv6 address");
        }
        break;
    }
    case AF_UNIX: {
        // UNIX socket
        struct sockaddr_un *addr_un = (struct sockaddr_un *)addr;
        if (addr_un->sun_path[0] == '\0') {
            snprintf(output, len, "Abstract: %s", addr_un->sun_path + 1); // Abstract socket
        } else {
            snprintf(output, len, "%s", addr_un->sun_path); // File path
        }
        break;
    }
    default:
        snprintf(output, len, "Unknown address family: %d", addr->sa_family);
        break;
    }
    return;
}

void init_recorder(){
    output_file = fopen(RECORDER_LOG_PATH, "w");
    // output_file = fopen("/ferry/my_trace/my_trace/output_partical.txt", "w");
    if (output_file == NULL) {
        fprintf(stderr, "open recorder_output_file failed\n");
        exit(EXIT_FAILURE);
    }
    char *buffer = (char *)malloc(BUFFER_SIZE);
    if (!buffer) {
        perror("Failed to allocate buffer");
        fclose(output_file);
        exit(EXIT_FAILURE);
    }
    if (setvbuf(output_file, buffer, _IOFBF, BUFFER_SIZE) != 0) {
        perror("Failed to set buffer");
        free(buffer);
        fclose(output_file);
        exit(EXIT_FAILURE);
    }
}

void update_recorder(long timestamp, void *data) {

    const struct Event *e = (struct Event *) data;
    char *process_type;
    if (e->info.pid == e->info.tgid) {
        process_type = (char *) "process";
    } else {
        process_type = (char *) "thread";
    }

    char *event_type;

    switch (e->info.syscall_id) {
        //PROCESS
        case __NR_clone:
        {
            event_type = (char *) "CLONE";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Flags\":0x%x} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.clone.flags
                    );
            break;
        }
        case __NR_clone3:
        {
            event_type = (char *) "CLONE3";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld"
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value
                    );
            break;
        }
        case __NR_execve:
        {
            event_type = (char *) "EXECVE";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Pathname\":\"%s\"} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.execve.pathname
                    );
            break;
        }
        case __NR_chdir:
        {
            event_type = (char *) "CHDIR";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Pathname\":\"%s\"} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.chdir.pathname
                    );
            break;
        }
        case __NR_fchdir:
        {
            event_type = (char *) "FCHDIR";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.fchdir.fd
                    );
            break;
        }
        case __NR_ptrace:
        {
            event_type = (char *)"PTRACE";

            char op_str[128] = {0};
            switch (e->args.ptrace.op) {
                case PTRACE_TRACEME:
                    strcpy(op_str, "PTRACE_TRACEME");
                    break;
                case PTRACE_PEEKTEXT:
                    strcpy(op_str, "PTRACE_PEEKTEXT");
                    break;
                case PTRACE_PEEKDATA:
                    strcpy(op_str, "PTRACE_PEEKDATA");
                    break;
                case PTRACE_PEEKUSER:
                    strcpy(op_str, "PTRACE_PEEKUSER");
                    break;
                case PTRACE_POKETEXT:
                    strcpy(op_str, "PTRACE_POKETEXT");
                    break;
                case PTRACE_POKEDATA:
                    strcpy(op_str, "PTRACE_POKEDATA");
                    break;
                case PTRACE_POKEUSER:
                    strcpy(op_str, "PTRACE_POKEUSER");
                    break;
                case PTRACE_CONT:
                    strcpy(op_str, "PTRACE_CONT");
                    break;
                case PTRACE_KILL:
                    strcpy(op_str, "PTRACE_KILL");
                    break;
                case PTRACE_SINGLESTEP:
                    strcpy(op_str, "PTRACE_SINGLESTEP");
                    break;
                case PTRACE_ATTACH:
                    strcpy(op_str, "PTRACE_ATTACH");
                    break;
                case PTRACE_DETACH:
                    strcpy(op_str, "PTRACE_DETACH");
                    break;
                case PTRACE_SYSCALL:
                    strcpy(op_str, "PTRACE_SYSCALL");
                    break;
                default:
                    snprintf(op_str, sizeof(op_str), "UNKNOWN(%d)", e->args.ptrace.op);
                    break;
            }
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"OP\":\"%s\", "
                                "\"Pid\":\"%d\"} "
                                "}\n",
                timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                e->info.tgid, process_type, e->info.return_value,
                op_str,
                e->args.ptrace.pid);
            break;
        }

        case __NR_exit: // trigered by ebpf "sched" tracepoint,not syscall.
        case __NR_exit_group:
        {
            event_type = (char *) "EXIT";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Status\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.exit.status
                    );
            break;
        }
        //FILE
        case __NR_openat:
        case __NR_open:
        case __NR_creat:
        {
            event_type = (char *) "OPEN_FILE";
            // if (is_path_in_mount(e->openFileArguments.open_filename, untrace_fs_mountpoint_list)) {
            //     break;
            // }
            char flags_str[256] = {0};
            switch (e->args.open.flags & O_ACCMODE) {
                case O_RDONLY:
                    strcat(flags_str, "O_RDONLY ");
                    break;
                case O_WRONLY:
                    strcat(flags_str, "O_WRONLY ");
                    break;
                case O_RDWR:
                    strcat(flags_str, "O_RDWR ");
                    break;
            }
            if (e->args.open.flags & O_CREAT) strcat(flags_str, "O_CREAT ");
            if (e->args.open.flags & O_EXCL) strcat(flags_str, "O_EXCL ");
            if (e->args.open.flags & O_NOCTTY) strcat(flags_str, "O_NOCTTY ");
            if (e->args.open.flags & O_TRUNC) strcat(flags_str, "O_TRUNC ");
            if (e->args.open.flags & O_APPEND) strcat(flags_str, "O_APPEND ");
            if (e->args.open.flags & O_NONBLOCK) strcat(flags_str, "O_NONBLOCK ");
            if (e->args.open.flags & O_DSYNC) strcat(flags_str, "O_DSYNC ");
            if (e->args.open.flags & O_SYNC) strcat(flags_str, "O_SYNC ");
            if (e->args.open.flags & O_RSYNC) strcat(flags_str, "O_RSYNC ");
            if (e->args.open.flags & O_DIRECTORY) strcat(flags_str, "O_DIRECTORY ");
            if (e->args.open.flags & O_NOFOLLOW) strcat(flags_str, "O_NOFOLLOW ");
            if (e->args.open.flags & O_CLOEXEC) strcat(flags_str, "O_CLOEXEC ");
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"DirFD\":%d, "
                                "\"Pathname\":\"%s\", "
                                "\"Flags\":\"%s\", "
                                "\"Mode\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.open.dirfd,
                    e->args.open.pathname,
                    flags_str,
                    e->args.open.mode
                    );
                    
            break;
        }
        case __NR_dup:
        case __NR_dup2:
        case __NR_dup3:
        {
            event_type = (char *) "DUP";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"OldFD\":%d, "
                                "\"NewFD\":%d, "
                                "\"Flags\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.dup.oldfd,
                    e->args.dup.newfd,
                    e->args.dup.flags
                    );
            break;
        }
        case __NR_fcntl:
        {
            event_type = (char *) "FCNTL";

            char cmd_str[128] = {0};
            char args_str[256] = {0};

            if (e->args.fcntl.cmd == F_GETFL) {
                strcpy(cmd_str, "F_GETFL");
            } else if (e->args.fcntl.cmd == F_SETFL) {
                strcpy(cmd_str, "F_SETFL");
                if (e->args.fcntl.args & O_NONBLOCK) strcat(args_str, "O_NONBLOCK ");
                if (e->args.fcntl.args & O_APPEND) strcat(args_str, "O_APPEND ");
                if (e->args.fcntl.args & O_RDWR) strcat(args_str, "O_RDWR ");
                if (e->args.fcntl.args & O_RDONLY) strcat(args_str, "O_RDONLY ");
                if (e->args.fcntl.args & O_WRONLY) strcat(args_str, "O_WRONLY ");
            } else if (e->args.fcntl.cmd == F_GETFD) {
                strcpy(cmd_str, "F_GETFD");
            } else if (e->args.fcntl.cmd == F_SETFD) {
                strcpy(cmd_str, "F_SETFD");
                if (e->args.fcntl.args & FD_CLOEXEC) strcat(args_str, "FD_CLOEXEC ");
            } else if (e->args.fcntl.cmd == F_DUPFD) {
                strcpy(cmd_str, "F_DUPFD");
                snprintf(args_str, sizeof(args_str), "min_fd: %d", e->args.fcntl.args);
            } else if (e->args.fcntl.cmd == F_DUPFD_CLOEXEC) {
                strcpy(cmd_str, "F_DUPFD_CLOEXEC");
                snprintf(args_str, sizeof(args_str), "min_fd: %d", e->args.fcntl.args);
            } else {
                snprintf(cmd_str, sizeof(cmd_str), "UNKNOWN(%d)", e->args.fcntl.cmd);
                snprintf(args_str, sizeof(args_str), "raw_args: %d", e->args.fcntl.args);
            }
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"CMD\":\"%s\", "
                                "\"Args\":\"%s\"} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.fcntl.fd,
                    cmd_str,
                    args_str
                    );
            break;
        }
        case __NR_close:
        {
            event_type = (char *) "CLOSE";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.close.fd
                    );
            break;
        }
        case __NR_unlinkat:
        case __NR_unlink:
        {
            event_type = (char *) "UNLINK";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"DirFD\":%d, "
                                "\"Pathname\":\"%s\","
                                "\"Flags\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.unlink.dirfd,
                    e->args.unlink.pathname,
                    e->args.unlink.flags
                    );
            break;
        }
        case __NR_read:
        case __NR_pread64:
        case __NR_readv:
        case __NR_preadv:
        case __NR_preadv2:
        {
            event_type = (char *) "READ";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Count\":\"%ld\","
                                "\"Offset\":%ld} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.read.fd,
                    e->args.read.count,
                    e->args.read.offset
                    );
            break;
        }
        case __NR_write:
        case __NR_pwrite64:
        case __NR_writev:
        case __NR_pwritev:
        case __NR_pwritev2:
        {
            event_type = (char *) "WRITE";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Count\":\"%ld\","
                                "\"Offset\":%ld} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.write.fd,
                    e->args.write.count,
                    e->args.write.offset
                    );
            break;
        }
        case __NR_truncate:
        {
            event_type = (char *) "TRUNCATE";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Pathname\":\"%s\","
                                "\"Length\":%ld} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.truncate.pathname,
                    e->args.truncate.length
                    );
            break;
        }
        case __NR_ftruncate:
        {
            event_type = (char *) "FTRUNCATE";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Length\":%ld} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.ftruncate.fd,
                    e->args.ftruncate.length
                    );
            break;
        }
        case __NR_rename:
        case __NR_renameat:
        case __NR_renameat2:
        {
            event_type = (char *) "RENAME";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"OldDirFD\":%d, "
                                "\"OldPath\":\"%s\", "
                                "\"NewDirFD\":%d, "
                                "\"NewPath\":\"%s\", "
                                "\"Flags\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.rename.olddirfd,
                    e->args.rename.oldpath,
                    e->args.rename.newdirfd,
                    e->args.rename.newpath,
                    e->args.rename.flags
                    );
            break;
        }
        case __NR_chmod:
        case __NR_fchmodat:
        {
            event_type = (char *) "CHMOD";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"DirFD\":%d, "
                                "\"Pathname\":\"%s\", "
                                "\"Mode\":%d, "
                                "\"Flags\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.chmod.dirfd,
                    e->args.chmod.pathname,
                    e->args.chmod.mode,
                    e->args.chmod.flags
                    );
            break;
        }
        case __NR_fchmod:
        {
            event_type = (char *) "FCHMOD";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Mode\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.fchmod.fd,
                    e->args.fchmod.mode
                    );
            break;
        }
        case __NR_stat:
        case __NR_lstat:
        {
            event_type = (char *) "STAT";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Pathname\":\"%s\"} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.stat.pathname
                    );
            break;
        }
        case __NR_fstat:
        {
            event_type = (char *) "FSTAT";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.fstat.fd
                    );
            break;
        }
        case __NR_newfstatat:
        {
            event_type = (char *) "FSTATAT";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"DirFD\":%d, "
                                "\"Pathname\":\"%s\", "
                                "\"Flags\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.fstatat.dirfd,
                    e->args.fstatat.pathname,
                    e->args.fstatat.flags
                    );
            break;
        }
        case __NR_statx:
        {
            event_type = (char *) "STATX";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"DirFD\":%d, "
                                "\"Pathname\":\"%s\", "
                                "\"Flags\":%d, "
                                "\"Mask\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.statx.dirfd,
                    e->args.statx.pathname,
                    e->args.statx.flags,
                    e->args.statx.mask
                    );
            break;
        }

        case __NR_socket:
        {
            event_type = (char *) "SOCKET";
            char family_str[64] = {0};
            char type_str[64] = {0};
            // char protocol_str[64] = {0};

            if (e->args.socket.domain == AF_INET) {
                strcat(family_str, "AF_INET");
            } else if (e->args.socket.domain == AF_INET6) {
                strcat(family_str, "AF_INET6");
            } else if (e->args.socket.domain == AF_UNIX) {
                strcat(family_str, "AF_UNIX");
            } else {
                snprintf(family_str, sizeof(family_str), "0x%x", e->args.socket.domain);
            }

            if (e->args.socket.type == SOCK_STREAM) {
                strcat(type_str, "SOCK_STREAM");
            } else if (e->args.socket.type == SOCK_DGRAM) {
                strcat(type_str, "SOCK_DGRAM");
            } else if (e->args.socket.type == SOCK_RAW) {
                strcat(type_str, "SOCK_RAW");
            } else if (e->args.socket.type == SOCK_SEQPACKET) {
                strcat(type_str, "SOCK_SEQPACKET");
            } else {
                snprintf(type_str, sizeof(type_str), "0x%x", e->args.socket.type);
            }

            // if (e->args.socket.protocol == IPPROTO_TCP) {
            //     strcat(protocol_str, "IPPROTO_TCP");
            // } else if (e->args.socket.protocol == IPPROTO_UDP) {
            //     strcat(protocol_str, "IPPROTO_UDP");
            // } else if (e->args.socket.protocol == IPPROTO_ICMP) {
            //     strcat(protocol_str, "IPPROTO_ICMP");
            // } else {
            //     snprintf(protocol_str, sizeof(protocol_str), "0x%x", e->args.socket.protocol);
            // }

            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Family\":\"%s\","
                                "\"Type\":\"%s\","
                                "\"Protocol\":\"%d\"} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type, e->info.return_value,
                    family_str,
                    type_str,
                    e->args.socket.protocol
                    // protocol_str
                    );
            break;
        }
        case __NR_bind:
        {
            event_type = (char *) "BIND";
            char addr_str[MAX_SOCKADDR_LEN];
            sockaddr_to_string((struct sockaddr *)&e->args.bind.addr, addr_str, sizeof(addr_str));
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Addr\":\"%s\", "
                                "\"AddrLen\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.bind.fd,
                    addr_str,
                    e->args.bind.addrlen
                    );
            break;
        }
        case __NR_listen:
        {
            event_type = (char *) "LISTEN";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Backlog\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.listen.fd,
                    e->args.listen.backlog
                    );
            break;
        }
        case __NR_connect:
        {
            event_type = (char *) "CONNECT";
            char addr_str[MAX_SOCKADDR_LEN];
            sockaddr_to_string((struct sockaddr *)&e->args.connect.addr, addr_str, sizeof(addr_str));
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Addr\":\"%s\", "
                                "\"AddrLen\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.connect.fd,
                    addr_str,
                    e->args.connect.addrlen
                    );
            break;
        }
        case __NR_accept:
        case __NR_accept4:
        {
            event_type = (char *) "ACCEPT";
            char addr_str[MAX_SOCKADDR_LEN];
            sockaddr_to_string((struct sockaddr *)&e->args.accept.addr, addr_str, sizeof(addr_str));
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Addr\":\"%s\", "
                                "\"AddrLen\":%d, "
                                "\"Flags\":0%o} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.accept.fd,
                    addr_str,
                    e->args.accept.addrlen,
                    e->args.accept.flags
                    );
            break;
        }
        case __NR_recvfrom:
        {
            event_type = (char *) "RECVFROM";
            char addr_str[MAX_SOCKADDR_LEN];
            sockaddr_to_string((struct sockaddr *)&e->args.recv.addr, addr_str, sizeof(addr_str));
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Len\":%lu, "
                                "\"Flags\":%d, "
                                "\"Addr\":\"%s\", "
                                "\"AddrLen\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.recv.fd,
                    e->args.recv.len,
                    e->args.recv.flags,
                    addr_str,
                    e->args.recv.addrlen
                    );
            break;
        }
        case __NR_recvmsg:
        case __NR_recvmmsg:
        {
            event_type = (char *) "RECVMSG";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Flags\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.recv.fd,
                    e->args.recv.flags
                    );
            break;
        }
        case __NR_sendto:
        {
            event_type = (char *) "SENDTO";
            char addr_str[MAX_SOCKADDR_LEN];
            sockaddr_to_string((struct sockaddr *)&e->args.send.addr, addr_str, sizeof(addr_str));
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Len\":%lu, "
                                "\"Flags\":%d, "
                                "\"Addr\":\"%s\", "
                                "\"AddrLen\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.send.fd,
                    e->args.send.len,
                    e->args.send.flags,
                    addr_str,
                    e->args.send.addrlen
                    );
            break;
        }
        case __NR_sendmsg:
        case __NR_sendmmsg:
        {
            event_type = (char *) "SENDMSG";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"FD\":%d, "
                                "\"Flags\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.send.fd,
                    e->args.send.flags
                    );
            break;
        }

        case __NR_mmap:
        {
            event_type = (char *) "MMAP";
            char prot_str[128] = {0};
            char flags_str[256] = {0};

            if (e->args.mmap.prot & PROT_READ) strcat(prot_str, "PROT_READ ");
            if (e->args.mmap.prot & PROT_WRITE) strcat(prot_str, "PROT_WRITE ");
            if (e->args.mmap.prot & PROT_EXEC) strcat(prot_str, "PROT_EXEC ");
            if (e->args.mmap.prot & PROT_NONE) strcat(prot_str, "PROT_NONE ");

            if (e->args.mmap.flags & MAP_SHARED) strcat(flags_str, "MAP_SHARED ");
            if (e->args.mmap.flags & MAP_PRIVATE) strcat(flags_str, "MAP_PRIVATE ");
            if (e->args.mmap.flags & MAP_ANONYMOUS) strcat(flags_str, "MAP_ANONYMOUS ");
            if (e->args.mmap.flags & MAP_FIXED) strcat(flags_str, "MAP_FIXED ");
            if (e->args.mmap.flags & MAP_POPULATE) strcat(flags_str, "MAP_POPULATE ");
            if (e->args.mmap.flags & MAP_NORESERVE) strcat(flags_str, "MAP_NORESERVE ");
            if (e->args.mmap.flags & MAP_LOCKED) strcat(flags_str, "MAP_LOCKED ");
            if (e->args.mmap.flags & MAP_HUGETLB) strcat(flags_str, "MAP_HUGETLB ");

            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%p, "
                                "\"Arguments\":{"
                                "\"Addr\":%p,"
                                "\"Length\":%ld,"
                                "\"Prot\":\"%s\","
                                "\"Flags\":\"%s\","
                                "\"FD\":%d,"
                                "\"Offset\":%ld} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,(void *)e->info.return_value,
                    e->args.mmap.addr,
                    e->args.mmap.length,
                    prot_str,
                    flags_str,
                    e->args.mmap.fd,
                    e->args.mmap.offset
                    );
            break;
        }
        case __NR_mprotect:
        {
            event_type = (char *) "MPROTECT";
            char prot_str[128] = {0};

            if (e->args.mprotect.prot & PROT_READ) strcat(prot_str, "PROT_READ ");
            if (e->args.mprotect.prot & PROT_WRITE) strcat(prot_str, "PROT_WRITE ");
            if (e->args.mprotect.prot & PROT_EXEC) strcat(prot_str, "PROT_EXEC ");
            if (e->args.mprotect.prot & PROT_NONE) strcat(prot_str, "PROT_NONE ");
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Addr\":%p,"
                                "\"Length\":%ld,"
                                "\"Prot\":\"%s\"} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.mprotect.addr,
                    e->args.mprotect.length,
                    prot_str
                    );
            break;
        }

        case __NR_munmap:{
            event_type = (char *) "MUNMAP";
            fprintf(output_file, "{"
                            "\"Timestamp\":%ld,"
                            "\"EventName\":\"%s\", "
                            "\"SyscallID\":\"%d\", "
                            "\"ProcessName\":\"%s\", "
                            "\"ProcessID\":%d, "
                            "\"ThreadID\":%d, "
                            "\"ProcessType\":\"%s\", "
                            "\"ReturnValue\":%ld, "
                            "\"Arguments\":{"
                            "\"Addr\":%p,"
                            "\"Length\":%ld} "
                            "}\n",
                timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                e->info.tgid, process_type,e->info.return_value,
                e->args.munmap.addr,
                e->args.munmap.length
                );
            break;
        }

        case __NR_shmget:
        {
            event_type = (char *) "SHMGET";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Key\":%d,"
                                "\"Size\":%lu,"
                                "\"Shmflg\":0%o} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.shmget.key,
                    e->args.shmget.size,
                    e->args.shmget.shmflg
                    );
            break;
        }
        case __NR_shmat:
        {
            event_type = (char *) "SHMAT";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%p, "
                                "\"Arguments\":{"
                                "\"Shmid\":%d,"
                                "\"Shmaddr\":%p,"
                                "\"Shmflg\":0%o} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,(void *)e->info.return_value,
                    e->args.shmat.shmid,
                    e->args.shmat.shmaddr,
                    e->args.shmat.shmflg
                    );
            break;
        }
        case __NR_shmdt:
        {
            event_type = (char *) "SHMDT";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Shmaddr\":%p} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.shmdt.shmaddr
                    );
            break;
        }
        case __NR_shmctl:
        {
            event_type = (char *) "SHMCTL";
            char cmd_str[128] = {0};

            if (e->args.shmctl.cmd == IPC_STAT) {
                strcat(cmd_str, "IPC_STAT");
            } else if (e->args.shmctl.cmd == IPC_SET) {
                strcat(cmd_str, "IPC_SET");
            } else if (e->args.shmctl.cmd == IPC_RMID) {
                strcat(cmd_str, "IPC_RMID");
            } else if (e->args.shmctl.cmd == SHM_LOCK) {
                strcat(cmd_str, "SHM_LOCK");
            } else if (e->args.shmctl.cmd == SHM_UNLOCK) {
                strcat(cmd_str, "SHM_UNLOCK");
            } else {
                snprintf(cmd_str, sizeof(cmd_str), "UNKNOWN_CMD(%d)", e->args.shmctl.cmd);
            }
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Shmid\":%d,"
                                "\"Cmd\":\"%s\"} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.shmctl.shmid,
                    cmd_str
                    );
            break;
        }

        case __NR_msgget:
        {
            event_type = (char *) "MSGGET";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Key\":%d,"
                                "\"Msgflg\":0%o} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.msgget.key,
                    e->args.msgget.msgflg
                    );
            break;
        }
        case __NR_msgsnd:
        {
            event_type = (char *) "MSGSND";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Msqid\":%d,"
                                "\"Msgsz\":%lu,"
                                "\"Msgflg\":0%o} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.msgsnd.msqid,
                    e->args.msgsnd.msgsz,
                    e->args.msgsnd.msgflg
                    );
            break;
        }
        case __NR_msgrcv:
        {
            event_type = (char *) "MSGRCV";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Msqid\":%d,"
                                "\"Msgsz\":%lu,"
                                "\"Msgtyp\":%ld,"
                                "\"Msgflg\":0%o} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.msgrcv.msqid,
                    e->args.msgrcv.msgsz,
                    e->args.msgrcv.msgtyp,
                    e->args.msgrcv.msgflg
                    );
            break;
        }
        case __NR_msgctl:
        {
            event_type = (char *) "MSGCTL";
            char cmd_str[128] = {0};

            if (e->args.msgctl.op == IPC_STAT) {
                strcat(cmd_str, "IPC_STAT");
            } else if (e->args.msgctl.op == IPC_SET) {
                strcat(cmd_str, "IPC_SET");
            } else if (e->args.msgctl.op == IPC_RMID) {
                strcat(cmd_str, "IPC_RMID");
            } else {
                snprintf(cmd_str, sizeof(cmd_str), "UNKNOWN_CMD(%d)", e->args.msgctl.op);
            }

            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Msqid\":%d,"
                                "\"Cmd\":\"%s\"} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type, e->info.return_value,
                    e->args.msgctl.msqid,
                    cmd_str
                    );
            break;
        }

        case __NR_mq_open:
        {
            event_type = (char *) "MQ_OPEN";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Name\":%s,"
                                "\"Oflag\":%d,"
                                "\"Mode\":%u} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.mqopen.name,
                    e->args.mqopen.oflag,
                    e->args.mqopen.mode
                    );
            break;
        }
        case __NR_mq_unlink:
        {
            event_type = (char *) "MQ_UNLINK";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Name\":%s} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.mqunlink.name
                    );
            break;
        }
        case __NR_mq_timedsend:
        {
            event_type = (char *) "MQ_TIMEDSEND";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Mqdes\":%d,"
                                "\"Msg_len\":%lu} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.mqmsg.mqdes,
                    e->args.mqmsg.msg_len
                    );
            break;
        }
        case __NR_mq_timedreceive:
        {
            event_type = (char *) "MQ_TIMEDRECEIVE";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Mqdes\":%d,"
                                "\"Msg_len\":%lu} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.mqmsg.mqdes,
                    e->args.mqmsg.msg_len
                    );
            break;
        }
        case __NR_mq_notify:
        {
            event_type = (char *) "MQ_TIMEDNOTIFY";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Mqdes\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.mqmsg.mqdes
                    );
            break;
        }
        case __NR_mq_getsetattr:
        {
            event_type = (char *) "MQ_TIMEDGETSETATTR";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Mqdes\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.mqmsg.mqdes
                    );
            break;
        }

        case __NR_pipe:
        case __NR_pipe2:
        {
            event_type = (char *) "PIPE";
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"EventName\":\"%s\", "
                                "\"SyscallID\":\"%d\", "
                                "\"ProcessName\":\"%s\", "
                                "\"ProcessID\":%d, "
                                "\"ThreadID\":%d, "
                                "\"ProcessType\":\"%s\", "
                                "\"ReturnValue\":%ld, "
                                "\"Arguments\":{"
                                "\"Fd_in\":%d,"
                                "\"Fd_out\":%d,"
                                "\"Flags\":%d} "
                                "}\n",
                    timestamp, event_type, e->info.syscall_id, e->info.comm, e->info.pid,
                    e->info.tgid, process_type,e->info.return_value,
                    e->args.pipe.fd_in,
                    e->args.pipe.fd_out,
                    e->args.pipe.flags
                    );
            break;
        }
        default:
        {
            fprintf(output_file, "{"
                                "\"Timestamp\":%ld,"
                                "\"SyscallID\":\"%d\""
                                "}\n",
                timestamp, e->info.syscall_id
                );
            break;
        }
    }
}

void cleanup_recorder(){
    if (output_file) {
        fflush(output_file);
        fclose(output_file);
        printf("recorder_output_file safely closed\n");
        output_file = NULL;
    }
}