#ifndef SYSCALL_EVENT_H
#define SYSCALL_EVENT_H

#define TASK_COMM_LEN 32
#define MAX_FILENAME_LEN 127
#define MAX_SOCKADDR_LEN 127
#define MAX_MSGNAME_LEN 127
// #define MAX_BUFF_LEN 100

#define QUEUE_SIZE 262144 // (256*1024)

// #include <pthread.h>
// #include <semaphore.h>

struct CommonInfo {
    // process id
    pid_t pid;
    pid_t tgid;

    // process name
    char comm[TASK_COMM_LEN];

    // event type
    int syscall_id;

    long timestamp;
    long return_value;
};

// PROCESS

struct CloneArguments {
    int flags;
};

struct Clone3Arguments {
};

struct ExecveArguments {
    char pathname[MAX_FILENAME_LEN];
};

struct ChdirArguments {
    char pathname[MAX_FILENAME_LEN];
};

struct FchdirArguments{
    int fd;
};

struct PtraceArguments{
    int op;
    pid_t pid;
};

struct ExitArguments{
    int status;
};

// FILE
struct OpenArguments {
    int dirfd;
    char pathname[MAX_FILENAME_LEN];
    int flags;
    short mode;
    long read_mem_ret;
    char *pathname_ptr;
};

struct DupArguments {
    int oldfd;
    int newfd;
    int flags;
};

struct FcntlArguments{
    int fd;
    int cmd;
    int args;
    // not save struct flock for cmd F_GETLK,F_SETLK and F_SETLKW
};

struct CloseArguments{
    int fd;
};

struct UnlinkArguments {
    int dirfd;
    char pathname[MAX_FILENAME_LEN];
    int flags;
};

struct ReadArguments{
    int fd;
    size_t count;
    off_t offset;
};

struct WriteArguments{
    int fd;
    size_t count;
    off_t offset;
};

struct TruncateArguments{
    char pathname[MAX_FILENAME_LEN];
    off_t length;
};

struct FtruncateArguments{
    int fd;
    off_t length;
};

struct RenameArguments{
    int olddirfd;
    char oldpath[MAX_FILENAME_LEN];
    int newdirfd;
    char newpath[MAX_FILENAME_LEN];
    unsigned int flags;
};

struct ChmodArguments{
    int dirfd;
    char pathname[MAX_FILENAME_LEN];
    mode_t mode;
    int flags;
};

struct FchmodArguments{
    int fd;
    mode_t mode;
};

struct StatArguments{
    char pathname[MAX_FILENAME_LEN];
};

struct FstatArguments{
    int fd;
};

struct FstatatArguments{
    int dirfd;
    char pathname[MAX_FILENAME_LEN];
    int flags;
};

struct StatxArguments{
    int dirfd;
    char pathname[MAX_FILENAME_LEN];
    int flags;
    unsigned int mask;
};

// SOCKET
struct SocketArguments{
    int domain;
    int type;
    int protocol;
};

struct BindArguments{ // also used by connect
    int fd;
    char addr[MAX_SOCKADDR_LEN]; 
    int addrlen; 
};

struct ListenArguments{
    int fd;
    int backlog; 
};

struct AcceptArguments{
    int fd;
    char addr[MAX_SOCKADDR_LEN]; 
    int addrlen; 
    int flags;
    char *addrptr;    
    long read_addr_ret;
};

struct RecvArguments{
    int fd;
    size_t len;
    int flags;
    char addr[MAX_SOCKADDR_LEN]; 
    int addrlen; 
    char *addrptr;
};

struct SendArguments{
    int fd;
    size_t len;
    int flags;
    char addr[MAX_SOCKADDR_LEN]; 
    int addrlen;
    char *addrptr;
};

// MEMORY
struct MmapArguments{
    void *addr;
    size_t length;
    int prot;
    int flags;
    int fd;
    off_t offset;
};

struct MprotectArguments{
    void *addr;
    size_t length;
    int prot;
};

struct MunmapArguments{
    void *addr;
    size_t length;
};

// SHARED MEMORY & MESSAGE QUEUE & PIPE
struct ShmgetArguments{
    key_t key;
    size_t size;
    int shmflg;
};

struct ShmatArguments{
    int shmid;
    void *shmaddr;
    int shmflg;
};

struct ShmdtArguments{
    void *shmaddr;
};

struct ShmctlArguments{
    int shmid;
    int cmd;
};

struct MsggetArguments{
    key_t key;
    int msgflg;
};

struct MsgsndArguments{
    int msqid;
    size_t msgsz;
    int msgflg;
};

struct MsgrcvArguments{
    int msqid;
    size_t msgsz;
    long msgtyp;
    int msgflg;
};

struct MsgctlArguments{
    int msqid;
    int op;
};

struct MqopenArguments{
    char name[MAX_MSGNAME_LEN];
    int oflag;
    mode_t mode;
};

struct MqunlinkArguments{
    char name[MAX_MSGNAME_LEN];
};

struct MqmsgArguments{ //for mq_timedsend & mq_timedreceive
    int mqdes;
    size_t msg_len;
};

struct MqnotifyArguments{
    int mqdes;
};

struct MqgetsetattrArguments{
    int mqdes;
};

struct PipeArguments{
    int fd_in;
    int fd_out;
    int flags;
    int *fd_ptr;
};

struct Event {
    struct CommonInfo info;
    union {
        struct CloneArguments clone;
        struct Clone3Arguments clone3;
        struct ExecveArguments execve;
        struct ChdirArguments chdir;
        struct FchdirArguments fchdir;
        struct PtraceArguments ptrace;
        struct ExitArguments exit;
        struct OpenArguments open;
        struct DupArguments dup;
        struct FcntlArguments fcntl;
        struct CloseArguments close;
        struct UnlinkArguments unlink;
        struct ReadArguments read;
        struct WriteArguments write;
        struct TruncateArguments truncate;
        struct FtruncateArguments ftruncate;
        struct RenameArguments rename;
        struct ChmodArguments chmod;
        struct FchmodArguments fchmod;
        struct StatArguments stat;
        struct FstatArguments fstat;
        struct FstatatArguments fstatat;
        struct StatxArguments statx;
        struct SocketArguments socket;
        struct BindArguments bind;
        struct ListenArguments listen;
        struct BindArguments connect;
        struct AcceptArguments accept;
        struct RecvArguments recv;
        struct SendArguments send;
        struct MmapArguments mmap;
        struct MprotectArguments mprotect;
        struct MunmapArguments munmap;
        struct ShmgetArguments shmget;
        struct ShmatArguments shmat;
        struct ShmdtArguments shmdt;
        struct ShmctlArguments shmctl;
        struct MsggetArguments msgget;
        struct MsgsndArguments msgsnd;
        struct MsgrcvArguments msgrcv;
        struct MsgctlArguments msgctl;
        struct MqopenArguments mqopen;
        struct MqunlinkArguments mqunlink;
        struct MqmsgArguments mqmsg;
        struct MqnotifyArguments mqnotify;
        struct MqgetsetattrArguments mqgetsetattr;
        struct PipeArguments pipe;
    } args;
};


#endif //SYSCALL_EVENT_H