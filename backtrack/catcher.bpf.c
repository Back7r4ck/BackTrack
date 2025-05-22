#include <vmlinux.h>
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <sys/syscall.h>
#include "syscall_event.h"
#include "config.h"

char LICENSE[] SEC("license") = "GPL";

//TODO:mknod,mknodat,pidfd_getfd,pidfd_open,mremap,process_vm_readv, process_vm_writev, execveat,memfd_create


#ifdef PARTIAL_TRACE

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PIDS);
    __type(key, u32);
    __type(value, u32);
} pid_bitmap SEC(".maps");

static __always_inline void set_pid_traced(u32 pid) {
    if (pid < MAX_PIDS && pid > 0) {
        u32 new_value = 1;
        bpf_map_update_elem(&pid_bitmap, &pid, &new_value, BPF_ANY);
    }
}

static __always_inline void unset_pid_traced(u32 pid) {
    if (pid < MAX_PIDS && pid > 0) {
        u32 new_value = 0;
        bpf_map_update_elem(&pid_bitmap, &pid, &new_value, BPF_ANY);
    }
}

static __always_inline int is_pid_traced(u32 pid) {
    u32 *bitmap_entry;

    bitmap_entry = bpf_map_lookup_elem(&pid_bitmap, &pid);
    return bitmap_entry ? *bitmap_entry : 0;
}
#endif  // PARTIAL_TRACE

// static const size_t EVENT_SIZE = sizeof(struct EVENT);
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
    // __uint(max_entries, EVENT_SIZE * 1024 * 1024);
} event_rb SEC(".maps");

// Use BPF_MAP_TYPE_PERCPU_HASH instead of BPF_MAP_TYPE_HASH because 
// sys_enter and sys_exit events for the same syscall are guaranteed
// to execute on the same CPU (no CPU migration during syscall handling).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct Event);
} event_cache SEC(".maps");

static __inline int my_memcmp(const char *a, const char *b, __u32 len)
{
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < len; i++) {
        if (a[i] != b[i]) return a[i] - b[i];
    }
    return 0;
}

static __always_inline bool partial_trace_filter_enter(struct trace_event_raw_sys_enter *ctx) {
    #ifdef PARTIAL_TRACE
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(comm, sizeof(comm));
        pid_t pid = bpf_get_current_pid_tgid();

        if (ctx->id == __NR_execve &&
            my_memcmp(comm, TARGET_COMM, TARGET_COMM_LEN) == 0) {
            set_pid_traced(pid);
        } else if (!is_pid_traced(pid)) {
            return false;
        }
    #else
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(&comm, sizeof(comm));
        if (my_memcmp(comm, IGNORE_COMM, IGNORE_COMM_LEN) == 0){
            return 0;
        }
    #endif //PARTIAL_TRACE
        return true;
}


#ifdef CAPTURE_CLONE
SEC("tracepoint/syscalls/sys_enter_clone")
int syscall_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.clone.flags = ctx->args[0];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int syscall_exit_clone(struct trace_event_raw_sys_exit *ctx){
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache){
        return 0;
    }

    #ifdef PARTIAL_TRACE
        if (ctx -> ret > 0 ){
            set_pid_traced(ctx -> ret);
        }
    
    #endif  // PARTIAL_TRACE

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);


    e->info.syscall_id = ctx->id;

    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);
    // e->info.is_process = e->info.pid == e->info.tgid;

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));
    // e->info.comm[0] = '\0';

    e->info.timestamp = bpf_ktime_get_ns()/1000;
    e->info.return_value = ctx -> ret;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

#endif /* CAPTURE_CLONE */

#ifdef CAPTURE_CLONE3
SEC("tracepoint/syscalls/sys_enter_clone3")
int syscall_enter_clone3(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;



    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int syscall_exit_clone3(struct trace_event_raw_sys_exit *ctx){
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache){
        return 0;
    }

    #ifdef PARTIAL_TRACE
        if (ctx -> ret > 0 ){
            set_pid_traced(ctx -> ret);
        }
    
    #endif  // PARTIAL_TRACE

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);


    e->info.syscall_id = ctx->id;

    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);
    // e->info.is_process = e->info.pid == e->info.tgid;

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));
    // e->info.comm[0] = '\0';

    e->info.timestamp = bpf_ktime_get_ns()/1000;
    e->info.return_value = ctx -> ret;

    bpf_ringbuf_submit(e, 0);

    return 0;
}
#endif /* CAPTURE_CLONE3 */

#ifdef CAPTURE_EXECVE
SEC("tracepoint/syscalls/sys_enter_execve")
int syscall_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    pathname_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&e.args.execve.pathname, sizeof(e.args.execve.pathname), pathname_ptr);

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int syscall_exit_execve(struct trace_event_raw_sys_exit *ctx){
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache){
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);


    e->info.syscall_id = ctx->id;

    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);
    // e->info.is_process = e->info.pid == e->info.tgid;

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));
    // e->info.comm[0] = '\0';

    e->info.timestamp = bpf_ktime_get_ns()/1000;
    e->info.return_value = ctx -> ret;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

#endif /* CAPTURE_EXECVE */

#ifdef CAPTURE_CHDIR
SEC("tracepoint/syscalls/sys_enter_chdir")
int syscall_enter_chdir(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    pathname_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&e.args.chdir.pathname, sizeof(e.args.chdir.pathname), pathname_ptr);

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int syscall_exit_chdir(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_CHDIR */

#ifdef CAPTURE_FCHDIR
SEC("tracepoint/syscalls/sys_enter_fchdir")
int syscall_enter_fchdir(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.fchdir.fd = ctx->args[0];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int syscall_exit_fchdir(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_FCHDIR */

#ifdef CAPTURE_PTRACE
SEC("tracepoint/syscalls/sys_enter_ptrace")
int syscall_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.ptrace.op = ctx->args[0];
    e.args.ptrace.pid = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ptrace")
int syscall_exit_ptrace(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_PTRACE */

#ifdef CAPTURE_EXIT
SEC("tracepoint/syscalls/sys_enter_exit")
int syscall_enter_exit(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    //e.args.exit.status = ctx->args[0];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_exit")
int syscall_exit_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_EXIT */

#ifdef CAPTURE_EXIT_GROUP
SEC("tracepoint/syscalls/sys_enter_exit_group")
int syscall_enter_exit_group(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    //e.args.exit.status = ctx->args[0];


    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_exit_group")
int syscall_exit_exit_group(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_EXIT_GROUP */

#ifdef CAPTURE_OPENAT
SEC("tracepoint/syscalls/sys_enter_openat")
int syscall_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.open.dirfd = ctx->args[0];
    e.args.open.pathname_ptr = (char *)ctx->args[1];
    e.args.open.read_mem_ret = bpf_probe_read_user_str(&e.args.open.pathname, sizeof(e.args.open.pathname), e.args.open.pathname_ptr);
    // if (e.args.open.debug_ret < 0) {
    //     e.args.open.debug_ret = bpf_probe_read_kernel_str(&e.args.open.pathname, sizeof(e.args.open.pathname), e.args.open.pathname_ptr);
    //     e.args.open.debug_ret = bpf_probe_read_str(&e.args.open.pathname, sizeof(e.args.open.pathname), e.args.open.pathname_ptr);
    // }
    e.args.open.flags = ctx->args[2];
    e.args.open.mode = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int syscall_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    if(e->args.open.read_mem_ret<0){
        e->args.open.read_mem_ret = bpf_probe_read_user_str(&e->args.open.pathname, sizeof(e->args.open.pathname), e->args.open.pathname_ptr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_OPENAT */

#ifdef CAPTURE_OPEN
SEC("tracepoint/syscalls/sys_enter_open")
int syscall_enter_open(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.open.dirfd = -100;
    pathname_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&e.args.open.pathname, sizeof(e.args.open.pathname), pathname_ptr);
    e.args.open.flags = ctx->args[1];
    e.args.open.mode = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int syscall_exit_open(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_OPEN */

#ifdef CAPTURE_CREAT
SEC("tracepoint/syscalls/sys_enter_creat")
int syscall_enter_creat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.open.dirfd = -100;
    pathname_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&e.args.open.pathname, sizeof(e.args.open.pathname), pathname_ptr);
    e.args.open.flags = -1;
    e.args.open.mode = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int syscall_exit_creat(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* CAPTURE_CREAT */

#ifdef CAPTURE_DUP
SEC("tracepoint/syscalls/sys_enter_dup")
int syscall_enter_dup(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.dup.oldfd = ctx->args[0];
    e.args.dup.newfd = -1;
    e.args.dup.flags = 0;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup")
int syscall_exit_dup(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_DUP */

#ifdef CAPTURE_DUP2
SEC("tracepoint/syscalls/sys_enter_dup2")
int syscall_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.dup.oldfd = ctx->args[0];
    e.args.dup.newfd = ctx->args[1];
    e.args.dup.flags = 0;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int syscall_exit_dup2(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_DUP2 */

#ifdef CAPTURE_DUP3
SEC("tracepoint/syscalls/sys_enter_dup3")
int syscall_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.dup.oldfd = ctx->args[0];
    e.args.dup.newfd = ctx->args[1];
    e.args.dup.flags = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup3")
int syscall_exit_dup3(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_DUP3 */

#ifdef CAPTURE_FCNTL
SEC("tracepoint/syscalls/sys_enter_fcntl")
int syscall_enter_fcntl(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.fcntl.fd = ctx->args[0];
    e.args.fcntl.cmd = ctx->args[1];
    e.args.fcntl.args = ctx->args[2];
    // not save struct flock for cmd F_GETLK,F_SETLK and F_SETLKW

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int syscall_exit_fcntl(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_FCNTL */

#ifdef CAPTURE_CLOSE
SEC("tracepoint/syscalls/sys_enter_close")
int syscall_enter_close(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.close.fd = ctx->args[0];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int syscall_exit_close(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* CAPTURE_CLOSE */

#ifdef CAPTURE_UNLINKAT
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int syscall_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.unlink.dirfd = ctx->args[0];
    pathname_ptr = (char *)ctx->args[1];
    bpf_probe_read_user_str(&e.args.unlink.pathname, sizeof(e.args.unlink.pathname), pathname_ptr);
    e.args.unlink.flags = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int syscall_exit_unlinkat(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_UNLINKAT */

#ifdef CAPTURE_UNLINK
SEC("tracepoint/syscalls/sys_enter_unlink")
int syscall_enter_unlink(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.unlink.dirfd = -100;
    pathname_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&e.args.unlink.pathname, sizeof(e.args.unlink.pathname), pathname_ptr);
    e.args.unlink.flags = -1;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int syscall_exit_unlink(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_UNLINK */

#ifdef CAPTURE_READ
SEC("tracepoint/syscalls/sys_enter_read")
int syscall_enter_read(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.read.fd = ctx->args[0];
    e.args.read.count = ctx->args[2];
    e.args.read.offset = -1;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int syscall_exit_read(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_READ */

#ifdef CAPTURE_PREAD64
SEC("tracepoint/syscalls/sys_enter_pread64")
int syscall_enter_pread64(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.read.fd = ctx->args[0];
    e.args.read.count = ctx->args[2];
    e.args.read.offset = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pread64")
int syscall_exit_pread64(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_PREAD64 */

#ifdef CAPTURE_READV
SEC("tracepoint/syscalls/sys_enter_readv")
int syscall_enter_readv(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.read.fd = ctx->args[0];
    e.args.read.count = -1;
    e.args.read.offset = -1;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int syscall_exit_readv(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_READV */

#ifdef CAPTURE_PREADV
SEC("tracepoint/syscalls/sys_enter_preadv")
int syscall_enter_preadv(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.read.fd = ctx->args[0];
    e.args.read.count = -1;
    e.args.read.offset = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_preadv")
int syscall_exit_preadv(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_PREADV */

#ifdef CAPTURE_PREADV2
SEC("tracepoint/syscalls/sys_enter_preadv2")
int syscall_enter_preadv2(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.read.fd = ctx->args[0];
    e.args.read.count = -1;
    e.args.read.offset = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_preadv2")
int syscall_exit_preadv2(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_PREADV2 */

#ifdef CAPTURE_WRITE
SEC("tracepoint/syscalls/sys_enter_write")
int syscall_enter_write(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.write.fd = ctx->args[0];
    e.args.write.count = ctx->args[2];
    e.args.write.offset = -1;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int syscall_exit_write(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_WRITE */

#ifdef CAPTURE_PWRITE64
SEC("tracepoint/syscalls/sys_enter_pwrite64")
int syscall_enter_pwrite64(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.write.fd = ctx->args[0];
    e.args.write.count = ctx->args[2];
    e.args.write.offset = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int syscall_exit_pwrite64(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_PWRITE64 */

#ifdef CAPTURE_WRITEV
SEC("tracepoint/syscalls/sys_enter_writev")
int syscall_enter_writev(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.write.fd = ctx->args[0];
    e.args.write.count = -1;
    e.args.write.offset = -1;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int syscall_exit_writev(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_WRITEV */

#ifdef CAPTURE_PWRITEV
SEC("tracepoint/syscalls/sys_enter_pwritev")
int syscall_enter_pwritev(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.write.fd = ctx->args[0];
    e.args.write.count = -1;
    e.args.write.offset = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwritev")
int syscall_exit_pwritev(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_PWRITEV */

#ifdef CAPTURE_PWRITEV2
SEC("tracepoint/syscalls/sys_enter_pwritev2")
int syscall_enter_pwritev2(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.write.fd = ctx->args[0];
    e.args.write.count = -1;
    e.args.write.offset = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwritev2")
int syscall_exit_pwritev2(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_PWRITEV2 */

#ifdef CAPTURE_TRUNCATE
SEC("tracepoint/syscalls/sys_enter_truncate")
int syscall_enter_truncate(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    pathname_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&e.args.truncate.pathname, sizeof(e.args.truncate.pathname), pathname_ptr);
    e.args.truncate.length = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_truncate")
int syscall_exit_truncate(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_TRUNCATE */

#ifdef CAPTURE_FTRUNCATE
SEC("tracepoint/syscalls/sys_enter_ftruncate")
int syscall_enter_ftruncate(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.ftruncate.fd = ctx->args[0];
    e.args.ftruncate.length = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ftruncate")
int syscall_exit_ftruncate(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_FTRUNCATE */

#ifdef CAPTURE_RENAME
SEC("tracepoint/syscalls/sys_enter_rename")
int syscall_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.rename.olddirfd = -100;
    pathname_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&e.args.rename.oldpath, sizeof(e.args.rename.oldpath), pathname_ptr);
    e.args.rename.newdirfd = -100;
    pathname_ptr = (char *)ctx->args[1];
    bpf_probe_read_user_str(&e.args.rename.newpath, sizeof(e.args.rename.newpath), pathname_ptr);
    e.args.rename.flags = -1;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int syscall_exit_rename(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_RENAME */

#ifdef CAPTURE_RENAMEAT
SEC("tracepoint/syscalls/sys_enter_renameat")
int syscall_enter_renameat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.rename.olddirfd = ctx->args[0];
    pathname_ptr = (char *)ctx->args[1];
    bpf_probe_read_user_str(&e.args.rename.oldpath, sizeof(e.args.rename.oldpath), pathname_ptr);
    e.args.rename.newdirfd = ctx->args[2];
    pathname_ptr = (char *)ctx->args[3];
    bpf_probe_read_user_str(&e.args.rename.newpath, sizeof(e.args.rename.newpath), pathname_ptr);
    e.args.rename.flags = -1;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int syscall_exit_renameat(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_RENAMEAT */

#ifdef CAPTURE_RENAMEAT2
SEC("tracepoint/syscalls/sys_enter_renameat2")
int syscall_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.rename.olddirfd = ctx->args[0];
    pathname_ptr = (char *)ctx->args[1];
    bpf_probe_read_user_str(&e.args.rename.oldpath, sizeof(e.args.rename.oldpath), pathname_ptr);
    e.args.rename.newdirfd = ctx->args[2];
    pathname_ptr = (char *)ctx->args[3];
    bpf_probe_read_user_str(&e.args.rename.newpath, sizeof(e.args.rename.newpath), pathname_ptr);
    e.args.rename.flags = ctx->args[4];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int syscall_exit_renameat2(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_RENAMEAT2 */

#ifdef CAPTURE_CHMOD
SEC("tracepoint/syscalls/sys_enter_chmod")
int syscall_enter_chmod(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.chmod.dirfd = -100;
    pathname_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&e.args.chmod.pathname, sizeof(e.args.chmod.pathname), pathname_ptr);
    e.args.chmod.mode = ctx->args[1];
    e.args.chmod.flags = -1;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chmod")
int syscall_exit_chmod(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_CHMOD */

#ifdef CAPTURE_FCHMODAT
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int syscall_enter_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.chmod.dirfd = ctx->args[0];
    pathname_ptr = (char *)ctx->args[1];
    bpf_probe_read_user_str(&e.args.chmod.pathname, sizeof(e.args.chmod.pathname), pathname_ptr);
    e.args.chmod.mode = ctx->args[2];
    e.args.chmod.flags = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int syscall_exit_fchmodat(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_FCHMODAT */

#ifdef CAPTURE_FCHMOD
SEC("tracepoint/syscalls/sys_enter_fchmod")
int syscall_enter_fchmod(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.fchmod.fd = ctx->args[0];
    e.args.fchmod.mode = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int syscall_exit_fchmod(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_FCHMOD */

#ifdef CAPTURE_STAT
SEC("tracepoint/syscalls/sys_enter_stat")
int syscall_enter_stat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    //     pathname_ptr = (char *)ctx->args[0];
    //     bpf_probe_read_user_str(&e.args.stat.pathname, sizeof(e.args.stat.pathname), pathname_ptr);

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_stat")
int syscall_exit_stat(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_STAT */

#ifdef CAPTURE_LSTAT
SEC("tracepoint/syscalls/sys_enter_lstat")
int syscall_enter_lstat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    //     pathname_ptr = (char *)ctx->args[0];
    //     bpf_probe_read_user_str(&e.args.stat.pathname, sizeof(e.args.stat.pathname), pathname_ptr);

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lstat")
int syscall_exit_lstat(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_LSTAT */

#ifdef CAPTURE_FSTAT
SEC("tracepoint/syscalls/sys_enter_fstat")
int syscall_enter_fstat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    //     e.args.fstat.fd = ctx->args[0]; 

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fstat")
int syscall_exit_fstat(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_FSTAT */

#ifdef CAPTURE_NEWFSTATAT
SEC("tracepoint/syscalls/sys_enter_newfstatat")
int syscall_enter_newfstatat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    //     e.args.fstatat.dirfd = ctx->args[0];
    //     pathname_ptr = (char *)ctx->args[1];
    //     bpf_probe_read_user_str(&e.args.fstatat.pathname, sizeof(e.args.fstatat.pathname), pathname_ptr);
    //     e.args.fstatat.flags = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newfstatat")
int syscall_exit_newfstatat(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_NEWFSTATAT */

#ifdef CAPTURE_STATX
SEC("tracepoint/syscalls/sys_enter_statx")
int syscall_enter_statx(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    //     e.args.statx.dirfd = ctx->args[0];
    //     pathname_ptr = (char *)ctx->args[1];
    //     bpf_probe_read_user_str(&e.args.statx.pathname, sizeof(e.args.statx.pathname), pathname_ptr);
    //     e.args.statx.flags = ctx->args[2];
    //     e.args.statx.mask = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_statx")
int syscall_exit_statx(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_STATX */

#ifdef CAPTURE_SOCKET
SEC("tracepoint/syscalls/sys_enter_socket")
int syscall_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.socket.domain = ctx->args[0];
    e.args.socket.type = ctx->args[1];
    e.args.socket.protocol = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int syscall_exit_socket(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_SOCKET */

#ifdef CAPTURE_BIND
SEC("tracepoint/syscalls/sys_enter_bind")
int syscall_enter_bind(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.bind.fd = ctx->args[0];
    e.args.bind.addrlen = ctx->args[2];
    sockaddr_ptr = (char *)BPF_CORE_READ(ctx, args[1]);// ctx->args[1] cannot bypass ebpf verifier
    
    bpf_probe_read_user(&e.args.bind.addr, 120, sockaddr_ptr);// bypass fxxking ebpf verifier

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int syscall_exit_bind(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_BIND */

#ifdef CAPTURE_LISTEN
SEC("tracepoint/syscalls/sys_enter_listen")
int syscall_enter_listen(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.listen.fd = ctx->args[0];
    e.args.listen.backlog = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_listen")
int syscall_exit_listen(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_LISTEN */

#ifdef CAPTURE_CONNECT
SEC("tracepoint/syscalls/sys_enter_connect")
int syscall_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.connect.fd = ctx->args[0];
    e.args.connect.addrlen = ctx->args[2];
    sockaddr_ptr = (char *)BPF_CORE_READ(ctx, args[1]);// ctx->args[1] cannot bypass ebpf verifier

    bpf_probe_read_user(&e.args.connect.addr, 120, sockaddr_ptr);// bypass fxxking ebpf verifier

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int syscall_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_CONNECT */

#ifdef CAPTURE_ACCEPT
SEC("tracepoint/syscalls/sys_enter_accept")
int syscall_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.accept.fd = ctx->args[0];
    e.args.accept.addrlen = ctx->args[2];
    // In "accept", arg "addr" are filled in by the kernel.
    // So Fetch in syscall_exit.
    e.args.accept.addrptr = (char *)ctx->args[1];
    e.args.accept.flags = 0;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int syscall_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;
    
    e->args.accept.read_addr_ret = bpf_probe_read_user(&e->args.accept.addr, 120, e->args.accept.addrptr);// bypass fxxking ebpf verifier
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_ACCEPT */

#ifdef CAPTURE_ACCEPT4
SEC("tracepoint/syscalls/sys_enter_accept4")
int syscall_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.accept.fd = ctx->args[0];
    e.args.accept.addrlen = ctx->args[2];
    // In "accept", arg "addr" are filled in by the kernel.
    // So Fetch in syscall_exit.
    e.args.accept.addrptr = (char *)ctx->args[1];
    e.args.accept.flags = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int syscall_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    e->args.accept.read_addr_ret = bpf_probe_read_user(&e->args.accept.addr, 120, e->args.accept.addrptr);// bypass fxxking ebpf verifier
   

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_ACCEPT4 */

#ifdef CAPTURE_RECVFROM
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int syscall_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.recv.fd = ctx->args[0];
    e.args.recv.len = ctx->args[2];
    e.args.recv.flags = ctx->args[3];
    e.args.recv.addrlen = ctx->args[5];
    // Arg "addr" are filled in by the kernel.
    // So Fetch in syscall_exit().
    e.args.recv.addrptr = (char *)BPF_CORE_READ(ctx, args[4]);// ctx->args[4] cannot bypass ebpf verifier

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int syscall_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    if(e->args.recv.addrptr != NULL){
        bpf_probe_read_user(&e->args.recv.addr, 120, e->args.recv.addrptr);// bypass fxxking ebpf verifier
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_RECVFROM */

#ifdef CAPTURE_RECVMSG
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int syscall_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.recv.fd = ctx->args[0];
    e.args.recv.flags = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int syscall_exit_recvmsg(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* CAPTURE_RECVMSG */

#ifdef CAPTURE_RECVMMSG
SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int syscall_enter_recvmmsg(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.recv.fd = ctx->args[0];
    e.args.recv.flags = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmmsg")
int syscall_exit_recvmmsg(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_RECVMMSG */

#ifdef CAPTURE_SENDTO
SEC("tracepoint/syscalls/sys_enter_sendto")
int syscall_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.send.fd = ctx->args[0];
    e.args.send.len = ctx->args[2];
    e.args.send.flags = ctx->args[3];
    e.args.send.addrlen = ctx->args[5];
    e.args.send.addrptr = (char *)BPF_CORE_READ(ctx, args[4]);// ctx->args[4] cannot bypass ebpf verifier
    
    if(e.args.send.addrptr != NULL){
        bpf_probe_read_user(&e.args.send.addr, 120, e.args.send.addrptr);// bypass fxxking ebpf verifier
    }

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int syscall_exit_sendto(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_SENDTO */

#ifdef CAPTURE_SENDMSG
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int syscall_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.send.fd = ctx->args[0];
    e.args.send.flags = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int syscall_exit_sendmsg(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_SENDMSG */

#ifdef CAPTURE_SENDMMSG
SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int syscall_enter_sendmmsg(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.send.fd = ctx->args[0];
    e.args.send.flags = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmmsg")
int syscall_exit_sendmmsg(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_SENDMMSG */

#ifdef CAPTURE_MMAP
SEC("tracepoint/syscalls/sys_enter_mmap")
int syscall_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.mmap.addr = (void *)ctx->args[0];
    e.args.mmap.length = ctx->args[1];
    e.args.mmap.prot = ctx->args[2];
    e.args.mmap.flags = ctx->args[3];
    e.args.mmap.fd = ctx->args[4];
    e.args.mmap.offset = ctx->args[5];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int syscall_exit_mmap(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MMAP */

#ifdef CAPTURE_MPROTECT
SEC("tracepoint/syscalls/sys_enter_mprotect")
int syscall_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.mprotect.addr = (void *)ctx->args[0];
    e.args.mprotect.length = ctx->args[1];
    e.args.mprotect.prot = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mprotect")
int syscall_exit_mprotect(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MPROTECT */

#ifdef CAPTURE_MUNMAP
SEC("tracepoint/syscalls/sys_enter_munmap")
int syscall_enter_munmap(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    //     e.args.munmap.addr = (void *)ctx->args[0];
    //     e.args.munmap.length = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_munmap")
int syscall_exit_munmap(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MUNMAP */

#ifdef CAPTURE_SHMGET
SEC("tracepoint/syscalls/sys_enter_shmget")
int syscall_enter_shmget(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.shmget.key = ctx->args[0];
    e.args.shmget.size = ctx->args[1];
    e.args.shmget.shmflg = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_shmget")
int syscall_exit_shmget(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_SHMGET */

#ifdef CAPTURE_SHMAT
SEC("tracepoint/syscalls/sys_enter_shmat")
int syscall_enter_shmat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.shmat.shmid = ctx->args[0];
    e.args.shmat.shmaddr = (void *)ctx->args[1];
    e.args.shmat.shmflg = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_shmat")
int syscall_exit_shmat(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_SHMAT */

#ifdef CAPTURE_SHMDT
SEC("tracepoint/syscalls/sys_enter_shmdt")
int syscall_enter_shmdt(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.shmdt.shmaddr = (void *)ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_shmdt")
int syscall_exit_shmdt(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_SHMDT */

#ifdef CAPTURE_SHMCTL
SEC("tracepoint/syscalls/sys_enter_shmctl")
int syscall_enter_shmctl(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.shmctl.shmid = ctx->args[0];
    e.args.shmctl.cmd = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_shmctl")
int syscall_exit_shmctl(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_SHMCTL */

#ifdef CAPTURE_MSGGET
SEC("tracepoint/syscalls/sys_enter_msgget")
int syscall_enter_msgget(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.msgget.key = ctx->args[0];
    e.args.msgget.msgflg = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_msgget")
int syscall_exit_msgget(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MSGGET */

#ifdef CAPTURE_MSGSND
SEC("tracepoint/syscalls/sys_enter_msgsnd")
int syscall_enter_msgsnd(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.msgsnd.msqid = ctx->args[0];
    e.args.msgsnd.msgsz = ctx->args[1];
    e.args.msgsnd.msgflg = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_msgsnd")
int syscall_exit_msgsnd(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MSGSND */

#ifdef CAPTURE_MSGRCV
SEC("tracepoint/syscalls/sys_enter_msgrcv")
int syscall_enter_msgrcv(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.msgrcv.msqid = ctx->args[0];
    e.args.msgrcv.msgsz = ctx->args[1];
    e.args.msgrcv.msgtyp = ctx->args[2];
    e.args.msgrcv.msgflg = ctx->args[3];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_msgrcv")
int syscall_exit_msgrcv(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MSGRCV */

#ifdef CAPTURE_MSGCTL
SEC("tracepoint/syscalls/sys_enter_msgctl")
int syscall_enter_msgctl(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.msgctl.msqid = ctx->args[0];
    e.args.msgctl.op = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_msgctl")
int syscall_exit_msgctl(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MSGCTL */

#ifdef CAPTURE_MQ_OPEN
SEC("tracepoint/syscalls/sys_enter_mq_open")
int syscall_enter_mq_open(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    pathname_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&e.args.mqopen.name, sizeof(e.args.mqopen.name), pathname_ptr);
    e.args.mqopen.oflag = ctx->args[1];
    e.args.mqopen.mode = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mq_open")
int syscall_exit_mq_open(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MQ_OPEN */

#ifdef CAPTURE_MQ_UNLINK
SEC("tracepoint/syscalls/sys_enter_mq_unlink")
int syscall_enter_mq_unlink(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    pathname_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&e.args.mqunlink.name, sizeof(e.args.mqunlink.name), pathname_ptr);

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mq_unlink")
int syscall_exit_mq_unlink(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MQ_UNLINK */

#ifdef CAPTURE_MQ_TIMEDSEND
SEC("tracepoint/syscalls/sys_enter_mq_timedsend")
int syscall_enter_mq_timedsend(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.mqmsg.mqdes = ctx->args[0];
    e.args.mqmsg.msg_len = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mq_timedsend")
int syscall_exit_mq_timedsend(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MQ_TIMEDSEND */

#ifdef CAPTURE_MQ_TIMEDRECEIVE
SEC("tracepoint/syscalls/sys_enter_mq_timedreceive")
int syscall_enter_mq_timedreceive(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.mqmsg.mqdes = ctx->args[0];
    e.args.mqmsg.msg_len = ctx->args[2];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mq_timedreceive")
int syscall_exit_mq_timedreceive(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* CAPTURE_MQ_TIMEDRECEIVE */

#ifdef CAPTURE_MQ_NOTIFY
SEC("tracepoint/syscalls/sys_enter_mq_notify")
int syscall_enter_mq_notify(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.mqnotify.mqdes = ctx->args[0];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mq_notify")
int syscall_exit_mq_notify(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MQ_NOTIFY */

#ifdef CAPTURE_MQ_GETSETATTR
SEC("tracepoint/syscalls/sys_enter_mq_getsetattr")
int syscall_enter_mq_getsetattr(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.mqgetsetattr.mqdes = ctx->args[0];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mq_getsetattr")
int syscall_exit_mq_getsetattr(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_MQ_GETSETATTR */

#ifdef CAPTURE_PIPE
SEC("tracepoint/syscalls/sys_enter_pipe")
int syscall_enter_pipe(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.pipe.fd_ptr = (int *)ctx->args[0];
    // Arg "pipefd" are filled in by the kernel.
    // So Fetch in syscall_exit().
    e.args.pipe.flags = 0;

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pipe")
int syscall_exit_pipe(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    int pipefd[2];
    bpf_probe_read_user(&pipefd, sizeof(pipefd), e->args.pipe.fd_ptr);
    e->args.pipe.fd_out = pipefd[0];
    e->args.pipe.fd_in = pipefd[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_PIPE */

#ifdef CAPTURE_PIPE2
SEC("tracepoint/syscalls/sys_enter_pipe2")
int syscall_enter_pipe2(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct Event e = {};
    char *pathname_ptr;
    char *sockaddr_ptr;

    if (!partial_trace_filter_enter(ctx))
        return 0;

    e.args.pipe.fd_ptr = (int *)ctx->args[0];
    // Arg "pipefd" are filled in by the kernel.
    // So Fetch in syscall_exit().
    e.args.pipe.flags = ctx->args[1];

    bpf_map_update_elem(&event_cache, &pid_tgid, &e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pipe2")
int syscall_exit_pipe2(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct Event *e_cache;
    e_cache = bpf_map_lookup_elem(&event_cache, &pid_tgid);
    if (!e_cache) {
        return 0;
    }

    struct Event *e;
    
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    __builtin_memcpy(e, e_cache, sizeof(*e));
    bpf_map_delete_elem(&event_cache, &pid_tgid);

    e->info.syscall_id = ctx->id;
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);

    bpf_get_current_comm(&e->info.comm, sizeof(e->info.comm));

    e->info.timestamp = bpf_ktime_get_ns() / 1000;
    e->info.return_value = ctx->ret;

    int pipefd[2];
    bpf_probe_read_user(&pipefd, sizeof(pipefd), e->args.pipe.fd_ptr);
    e->args.pipe.fd_out = pipefd[0];
    e->args.pipe.fd_in = pipefd[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* CAPTURE_PIPE2 */




SEC("tracepoint/sched/sched_process_exit")
// exit() and exit_group() cannot be caught by syscalls.
// so use sched to record process exit.
int handle_exit(struct pt_regs *ctx) { 
    u64 pid_tgid = bpf_get_current_pid_tgid();
#ifdef PARTIAL_TRACE
    if (!is_pid_traced((u32)pid_tgid)){
        return 0;
    }
    else{
        unset_pid_traced((u32)pid_tgid);
    }
#endif  // PARTIAL_TRACE

    struct Event *e;
    e = bpf_ringbuf_reserve(&event_rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    // e->args.exit.status = ctx->args[0];

    e->info.syscall_id = __NR_exit_group;
    
    e->info.pid = (u32)pid_tgid;
    e->info.tgid = (u32)(pid_tgid >> 32);
    e->info.timestamp = bpf_ktime_get_ns()/1000;
    // e->info.is_process = (e->info.pid == e->info.tgid);

    bpf_ringbuf_submit(e, 0);
    return 0;
}