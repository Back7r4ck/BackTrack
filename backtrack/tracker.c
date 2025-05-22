#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/shm.h>

#include "uthash.h"
#include "tracker.h"
#include "md5.h"
#include "syscall_event.h"
#include "config.h"

#define  BUFFER_SIZE 1024*1024

process_node *tracker_process_table = NULL;
FILE *tracker_output_file;
shm_node *shm_table = NULL;
msq_node *msq_table = NULL;
mq_node *mq_table = NULL;

void uuid_unparse(const uuid_t uuid, char *out) {
    sprintf(out, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            uuid[0], uuid[1], uuid[2], uuid[3], 
            uuid[4], uuid[5], uuid[6], uuid[7], 
            uuid[8], uuid[9], uuid[10], uuid[11], 
            uuid[12], uuid[13], uuid[14], uuid[15]);
}

void generate_uuid_process(pid_t pid, uuid_t uuid_out) {
    srand((unsigned)time(NULL) ^ pid);

    for (int i = 0; i < 10; i++) {
        uuid_out[i] = (unsigned char)(rand() % 256);
    }
    uuid_out[0] = uuid_out[0]&0x0F;

    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    long long hex_as_int = strtol(pid_str, NULL, 16);
    unsigned char pid_bytes[6];
    pid_bytes[0] = (unsigned char)((hex_as_int >> 40) & 0xFF);
    pid_bytes[1] = (unsigned char)((hex_as_int >> 32) & 0xFF);
    pid_bytes[2] = (unsigned char)((hex_as_int >> 24) & 0xFF);
    pid_bytes[3] = (unsigned char)((hex_as_int >> 16) & 0xFF);
    pid_bytes[4] = (unsigned char)((hex_as_int >> 8) & 0xFF);
    pid_bytes[5] = (unsigned char)(hex_as_int & 0xFF);

    memcpy(uuid_out + 10, pid_bytes, 6);
}

void get_uuid_fd_unparse(const char *filename, int fd_type, char *uuid_unparsed) {
    unsigned char hash[16];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, (unsigned char *)filename, strlen(filename));
    MD5_Final(hash, &md5);

    uuid_t uuid_raw;
    memcpy(uuid_raw, hash, 16);

    if(fd_type&FD_SOCKET){
        uuid_raw[0] = (uuid_raw[0]&0x0F)|0x20;
        uuid_unparse(uuid_raw,uuid_unparsed);
        return;
    }
    if(fd_type&FD_PIPE){
        uuid_raw[0] = (uuid_raw[0]&0x0F)|0x50;
        uuid_unparse(uuid_raw,uuid_unparsed);
        return;
    }
    uuid_raw[0] = (uuid_raw[0]&0x0F)|0x10;
    uuid_unparse(uuid_raw,uuid_unparsed);
    return;
    
}

void generate_uuid_shm(int shmid, uuid_t uuid_out) {
    srand((unsigned)time(NULL) ^ shmid);

    for (int i = 0; i < 10; i++) {
        uuid_out[i] = (unsigned char)(rand() % 256);
    }
    uuid_out[0] = ((uuid_out[0]&0x0F)|0x30) ;

    char shmid_str[16];
    snprintf(shmid_str, sizeof(shmid_str), "%d", shmid);
    long long hex_as_int = strtol(shmid_str, NULL, 16);
    unsigned char shmid_bytes[6];
    shmid_bytes[0] = (unsigned char)((hex_as_int >> 40) & 0xFF);
    shmid_bytes[1] = (unsigned char)((hex_as_int >> 32) & 0xFF);
    shmid_bytes[2] = (unsigned char)((hex_as_int >> 24) & 0xFF);
    shmid_bytes[3] = (unsigned char)((hex_as_int >> 16) & 0xFF);
    shmid_bytes[4] = (unsigned char)((hex_as_int >> 8) & 0xFF);
    shmid_bytes[5] = (unsigned char)(hex_as_int & 0xFF);

    memcpy(uuid_out + 10, shmid_bytes, 6);
}

void generate_uuid_msq(int msqid, uuid_t uuid_out) {
    srand((unsigned)time(NULL) ^ msqid);

    for (int i = 0; i < 10; i++) {
        uuid_out[i] = (unsigned char)(rand() % 256);
    }
    uuid_out[0] = ((uuid_out[0]&0x0F)|0x40) ;

    char msqid_str[16];
    snprintf(msqid_str, sizeof(msqid_str), "%d", msqid);
    long long hex_as_int = strtol(msqid_str, NULL, 16);
    unsigned char msqid_bytes[6];
    msqid_bytes[0] = (unsigned char)((hex_as_int >> 40) & 0xFF);
    msqid_bytes[1] = (unsigned char)((hex_as_int >> 32) & 0xFF);
    msqid_bytes[2] = (unsigned char)((hex_as_int >> 24) & 0xFF);
    msqid_bytes[3] = (unsigned char)((hex_as_int >> 16) & 0xFF);
    msqid_bytes[4] = (unsigned char)((hex_as_int >> 8) & 0xFF);
    msqid_bytes[5] = (unsigned char)(hex_as_int & 0xFF);

    memcpy(uuid_out + 10, msqid_bytes, 6);
}

void get_uuid_mq_unparse(const char *name, char *uuid_unparsed) {
    unsigned char hash[16];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, (unsigned char *)name, strlen(name));
    MD5_Final(hash, &md5);

    uuid_t uuid_raw;
    memcpy(uuid_raw, hash, 16);

    uuid_raw[0] = (uuid_raw[0]&0x0F)|0x40;
    uuid_unparse(uuid_raw,uuid_unparsed);
}

fd_node *add_fd(process_node *proc, int fd_num, int type, int is_cloexec) {
    delete_fd(proc,fd_num);
    fd_node *new_fd = (fd_node *)malloc(sizeof(fd_node));
    if (!new_fd) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    new_fd->fd_num = fd_num;
    new_fd->type = type;
    new_fd->is_cloexec = is_cloexec;
    new_fd->read_bytes = 0;
    new_fd->read_count = 0;
    new_fd->write_bytes = 0;
    new_fd->write_count = 0;
    new_fd->name[0] = '\0';
    new_fd->bindname[0] = '\0';

    HASH_ADD_INT(proc->fd_table, fd_num, new_fd);
    return new_fd;
}

void inherit_fd_table(process_node *parent_proc, process_node *child_proc, long timestamp) {
    fd_node *fd, *new_fd;
    
    for (fd = parent_proc->fd_table; fd != NULL; fd = fd->hh.next) {
        new_fd = (fd_node *)malloc(sizeof(fd_node));
        if (!new_fd) {
            perror("malloc failed");
            exit(EXIT_FAILURE);
        }

        new_fd->fd_num = fd->fd_num;
        new_fd->type = fd->type;
        new_fd->is_cloexec = fd->is_cloexec;
        new_fd->read_bytes = 0;
        new_fd->read_count = 0;
        new_fd->write_bytes = 0;
        new_fd->write_count = 0;
        strcpy(new_fd->name,fd->name);
        strcpy(new_fd->bindname,fd->bindname);

        HASH_ADD_INT(child_proc->fd_table, fd_num, new_fd);

        // outputting inherited anonymous shared memory 
        char uuid_str_from[37];
        char uuid_str_to[37];
        if(new_fd->type == FD_MEMORY){
            uuid_unparse(child_proc->uuid, uuid_str_from);
            get_uuid_fd_unparse(new_fd->name, new_fd->type,uuid_str_to);
            fprintf(tracker_output_file, "{"
                    "\"LogType\":\"edge\","
                    "\"Timestamp\":%ld,"
                    "\"FromUUID\":\"%s\", "
                    "\"ToUUID\":\"%s\", "
                    "\"EventName\":\"MMAP(triggered by clone)\", "
                    "\"SyscallID\":%d, "
                    "\"ToName\":\"%s\""
                    "}\n",
            timestamp, uuid_str_from, uuid_str_to, __NR_mmap, new_fd->name
            );
            fprintf(tracker_output_file, "{"
                    "\"LogType\":\"edge\","
                    "\"Timestamp\":%ld,"
                    "\"FromUUID\":\"%s\", "
                    "\"ToUUID\":\"%s\", "
                    "\"EventName\":\"MMAP(triggered by clone)\", "
                    "\"SyscallID\":%d, "
                    "\"FromName\":\"%s\""
                    "}\n",
            timestamp, uuid_str_to, uuid_str_from, __NR_mmap, new_fd->name
            );
        }
    }
}

void execute_cloexec(process_node *proc) {
    fd_node *fd;
    void *tmp;
    
    for (fd = proc->fd_table; fd != NULL; fd = tmp) {
        tmp = fd->hh.next;
        if (fd->is_cloexec) {
            HASH_DEL(proc->fd_table, fd);
            free(fd);
        }
    }
}

fd_node *find_fd(process_node *proc, int fd_num) {
    fd_node *fd;
    HASH_FIND_INT(proc->fd_table, &fd_num, fd);
    return fd;
}

void delete_fd(process_node *proc, int fd_num) {
    fd_node *fd = find_fd(proc, fd_num);
    if (fd) {
        HASH_DEL(proc->fd_table, fd);
        free(fd);
    }
}

void traverse_fd(process_node *proc, int fd_num) {
    fd_node *fd = find_fd(proc, fd_num);
    if (fd) {
        HASH_DEL(proc->fd_table, fd);
        free(fd);
    }
}

shm_node *add_shm(int shmid) {// not overwrite if exist
    shm_node *node = NULL;

    HASH_FIND_INT(shm_table, &shmid, node);
    if (node == NULL) {
        node = (shm_node *)malloc(sizeof(shm_node));
        if (node == NULL) {
            perror("malloc failed");
            exit(EXIT_FAILURE);
        }
        node->shmid = shmid;
        generate_uuid_shm(shmid, node->uuid);

        HASH_ADD_INT(shm_table, shmid, node);
    }
    return node;
}

shm_node *find_shm(int shmid) {// find and create if not exist
    return add_shm(shmid);
}

void delete_shm(int shmid) {
    shm_node *node = NULL;
    HASH_FIND_INT(shm_table, &shmid, node);
    if (node) {
        HASH_DEL(shm_table, node);
        free(node);
    }
}

msq_node *add_msq(int msqid) {// not overwrite if exist
    msq_node *node = NULL;

    HASH_FIND_INT(msq_table, &msqid, node);
    if (node == NULL) {
        node = (msq_node *)malloc(sizeof(msq_node));
        if (node == NULL) {
            perror("malloc failed");
            exit(EXIT_FAILURE);
        }
        node->msqid = msqid;
        generate_uuid_msq(msqid, node->uuid);

        HASH_ADD_INT(msq_table, msqid, node);
    }
    return node;
}

msq_node *find_msq(int msqid) {// find and create if not exist
    return add_msq(msqid);
}

void delete_msq(int msqid) {
    msq_node *node = NULL;
    HASH_FIND_INT(msq_table, &msqid, node);
    if (node) {
        HASH_DEL(msq_table, node);
        free(node);
    }
}

mq_node *add_mq(int mqdes) {// not overwrite if exist
    mq_node *node = NULL;

    HASH_FIND_INT(mq_table, &mqdes, node);
    if (node == NULL) {
        node = (mq_node *)malloc(sizeof(mq_node));
        if (node == NULL) {
            perror("malloc failed");
            exit(EXIT_FAILURE);
        }
        node->mqdes = mqdes;

        HASH_ADD_INT(mq_table, mqdes, node);
    }
    return node;
}

mq_node *find_mq(int mqdes) {
    mq_node *node = NULL;
    HASH_FIND_INT(mq_table, &mqdes, node);
    return node;
}

void delete_mq(const char *name) {
    mq_node *node, *tmp;
    HASH_ITER(hh, mq_table, node, tmp) {
        if (strcmp(node->name, name) == 0) {
            HASH_DEL(mq_table, node);
            free(node);
            return;
        }
    }
}

process_node *add_process(pid_t pid) {// overwrite if exist
    delete_process(pid);
    process_node *proc = (process_node *)malloc(sizeof(process_node));
    if (!proc) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    generate_uuid_process(pid, proc->uuid);
    char uuid_str[37];
    uuid_unparse(proc->uuid, uuid_str);
    // printf("add_process: pid:%d,uuid:%s\n",pid,uuid_str);
    proc->pid = pid;
    proc->fd_table = NULL;

    HASH_ADD_INT(tracker_process_table, pid, proc);
    return proc;
}

process_node *find_process(pid_t pid) {
    process_node *proc;
    HASH_FIND_INT(tracker_process_table, &pid, proc);
    return proc;
}

void delete_process(pid_t pid) {
    process_node *proc = find_process(pid);
    if (proc) {
        fd_node *fd, *tmp;
        HASH_ITER(hh, proc->fd_table, fd, tmp) {
            HASH_DEL(proc->fd_table, fd);
            free(fd);
        }

        HASH_DEL(tracker_process_table, proc);
        free(proc);
    }
}

void free_all_processes() {
    process_node *proc, *tmp;
    HASH_ITER(hh, tracker_process_table, proc, tmp) {
        delete_process(proc->pid);
    }
}

void print_all_processes() {
    process_node *proc;
    fd_node *fd;
    for (proc = tracker_process_table; proc != NULL; proc = (process_node *)(proc->hh.next)) {
        char uuid_str[37];
        uuid_unparse(proc->uuid, uuid_str);
        printf("pid: %d, uuid: %s\n", proc->pid, uuid_str);
        for (fd = proc->fd_table; fd != NULL; fd = (fd_node *)(fd->hh.next)) {
            printf("\tFD: %d, Type: 0x%x, Is_cloexec: 0x%x, read_count:%ld, write_count:%ld, read_bytes:%ld, write_bytes:%ld, Name: %s, BindName: %s\n", 
                fd->fd_num, fd->type, fd->is_cloexec, fd->read_count, fd->write_count, fd->read_bytes, fd->write_bytes, fd->name, fd->bindname);
        }
    }
}

int get_process_cwd(pid_t pid, char *cwd, size_t size) {
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
    
    ssize_t len = readlink(path, cwd, size - 1);
    if (len == -1) {
        // perror("readlink");
        // printf("readlink failed in get_process_cwd, pid:%d\n", pid);
        return -1;
    }

    cwd[len] = '\0';
    printf("PID: %d,Current working directory (cwd): %s\n", pid, cwd);
    return 0;
}

void normalize_path(char *path) {
    char result[MAX_PATH_LEN];
    char *token;
    char *stack[MAX_PATH_LEN];
    int stack_index = 0;
    
    strncpy(result, path, MAX_PATH_LEN - 1);
    result[MAX_PATH_LEN - 1] = '\0';

    token = strtok(result, "/");
    
    while (token != NULL) {
        if (strcmp(token, ".") == 0 || token[0] == '\0') {
        } else if (strcmp(token, "..") == 0) {
            if (stack_index > 0) {
                stack_index--;
            }
        } else {
            stack[stack_index++] = token;
        }
        token = strtok(NULL, "/");
    }
    
    path[0] = '\0';
    if (stack_index == 0) {
        strcat(path, "/");
    } else {
        for (int i = 0; i < stack_index; i++) {
            strcat(path, "/");
            strcat(path, stack[i]);
        }
    }
}

void join_and_normalize_path(const char *base_path, const char *relative_path, char *result_path) {
    snprintf(result_path, MAX_PATH_LEN, "%s/%s", base_path, relative_path);
    
    normalize_path(result_path);
}

int get_process_fd_info(process_node *proc, int fd_num) {
    char path[MAX_PATH_LEN];
    char flags_path[MAX_PATH_LEN];
    char name[MAX_PATH_LEN];
    ssize_t len;
    FILE *flag_file;
    int flag_val = -1;
    pid_t pid = proc->pid;

    // printf("ready to fetch, pid:%d, fd:%d\n", pid, fd_num);
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd_num);
    len = readlink(path, name, sizeof(name));
    if (len == -1) {
        // perror("readlink");
        // printf("readlink failed in get_process_fd_info, pid:%d, fd:%d\n", pid, fd_num);
        return -1;
    }
    name[len] = '\0';

    snprintf(flags_path, sizeof(flags_path), "/proc/%d/fdinfo/%d", pid, fd_num);
    flag_file = fopen(flags_path, "r");
    // if (flag_file == NULL) {
    //     // perror("fopen");
    //     printf("fopen failed in get_process_fd_info, pid:%d, fd:%d\n", pid, fd_num);
    //     return -1;
    // }

    // char line[256];
    // while (fgets(line, sizeof(line), flag_file)) {
    //     if (sscanf(line, "flags: %x", &flag_val) == 1) {
    //         // printf("Flags: 0x%x\n", flag_val);
    //         break;
    //     }
    // }
    // if(flag_val == -1){
    //     printf("fscanf fdinfo failed in get_process_fd_info, pid:%d, fd:%d\n", pid, fd_num);
    //     fclose(flag_file);
    //     return -1;
    // }

    //set FD_CLOEXEC if fetch fdinfo failed
    if (flag_file != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), flag_file)) {
            if (sscanf(line, "flags: %x", &flag_val) == 1) {
                // printf("Flags: 0x%x\n", flag_val);
                break;
            }
        }
        if(flag_val == -1){
            flag_val = FD_CLOEXEC;
        }
        fclose(flag_file);
    }
    else{
        flag_val = FD_CLOEXEC;
    }

    fd_node *new_fd = add_fd(proc, fd_num, FD_UNKNOWN, flag_val&FD_CLOEXEC);
    strcpy(new_fd->name,name);
    
    printf("PID: %d, FD: %d, Path: %s, Is_cloexec: %d\n", pid, fd_num, new_fd->name, new_fd->is_cloexec);

    return 0;
}

const char *sockaddr_parse(const struct sockaddr *addr, char *output, size_t output_len) {
    if (!addr || !output || output_len == 0) {
        printf("sockaddr_parse Invalid input\n");
        return output;
    }

    switch (addr->sa_family) {
    case AF_INET: {
        // IPv4 address
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr_in->sin_addr, ip, sizeof(ip))) {
            snprintf(output, output_len, "%s:%d", ip, ntohs(addr_in->sin_port));
        } else {
            printf("sockaddr_parse Invalid IPv4 address\n");
        }
        break;
    }
    case AF_INET6: {
        // IPv6 address
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        char ip[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip, sizeof(ip))) {
            snprintf(output, output_len, "[%s]:%d", ip, ntohs(addr_in6->sin6_port));
        } else {
            printf("sockaddr_parse Invalid IPv6 address\n");
        }
        break;
    }
    case AF_UNIX: {
        // Unix domain socket
        struct sockaddr_un *addr_un = (struct sockaddr_un *)addr;
        if (addr_un->sun_path[0] == '\0') {
            snprintf(output, output_len, "Abstract: %s", addr_un->sun_path + 1); //Abstract Unix Domain Sockets
        } else {
            snprintf(output, output_len, "%s", addr_un->sun_path);
        }
        break;
    }
    default:
        printf("sockaddr_parse Unknown address family\n");
        break;
    }
    return output;
}

void init_tracker(){
    tracker_output_file = fopen(TRACKER_LOG_PATH, "w");
    // tracker_output_file = fopen("/ferry/my_trace/my_trace/output_partical_tracker.txt", "w");
    if (tracker_output_file == NULL) {
        fprintf(stderr, "open tracker_output_file failed\n");
        exit(EXIT_FAILURE);
    }

    char *buffer = (char *)malloc(BUFFER_SIZE);
    if (!buffer) {
        perror("Failed to allocate buffer");
        fclose(tracker_output_file);
        exit(EXIT_FAILURE);
    }
    if (setvbuf(tracker_output_file, buffer, _IOFBF, BUFFER_SIZE) != 0) {
        perror("Failed to set buffer");
        free(buffer);
        fclose(tracker_output_file);
        exit(EXIT_FAILURE);
    }
}

void update_tracker(long timestamp, void *data){
    const struct Event *e = (struct Event *) data;

    char uuid_str_from[37];
    char uuid_str_to[37];
    char absolute_path[MAX_PATH_LEN];
    char absolute_path2[MAX_PATH_LEN];
    switch (e->info.syscall_id) {
        //PROCESS
        case __NR_clone:
        case __NR_clone3: // TODO (maybe):clone3 is not commonly used
        {
            process_node *child_proc = add_process(e->info.return_value);
            
            process_node *parent_proc = find_process(e->info.pid);
            if(parent_proc!=NULL){
                inherit_fd_table(parent_proc, child_proc, timestamp);
                uuid_unparse(parent_proc->uuid, uuid_str_from);
            }
            else{
                parent_proc = add_process(e->info.pid);
                if (get_process_cwd(e->info.pid, parent_proc->pwd, sizeof(parent_proc->pwd))!=0){
                    parent_proc->pwd[0] = '\0';// means tracking pwd failed
                }
                uuid_unparse(parent_proc->uuid, uuid_str_from);
                fprintf(tracker_output_file, "{"
                            "\"LogType\":\"node\","
                            "\"UUID\":\"%s\", "
                            "\"NodeName\":\"%s\", "
                            "\"NodeType\":\"process\", "
                            "\"ProcessID\":%d, "
                            "\"ThreadID\":%d"
                            "}\n",
                uuid_str_from, e->info.comm, e->info.pid,e->info.tgid
                );
            }

            if(parent_proc->pwd[0] == '\0'){
                if (get_process_cwd((pid_t)e->info.return_value, child_proc->pwd, sizeof(child_proc->pwd))!=0){
                    child_proc->pwd[0] = '\0';// means tracking pwd failed
                }
            }
            else{
                strcpy(child_proc->pwd,parent_proc->pwd);
            }

            uuid_unparse(child_proc->uuid, uuid_str_to);
            fprintf(tracker_output_file, "{"
                        "\"LogType\":\"node\","
                        "\"UUID\":\"%s\", "
                        "\"NodeName\":\"%s\", "
                        "\"NodeType\":\"process\", "
                        "\"ProcessID\":%ld, "
                        "\"ThreadID\":%d"
                        "}\n",
            uuid_str_to, e->info.comm, e->info.return_value,e->info.tgid
            );

            fprintf(tracker_output_file, "{"
                        "\"LogType\":\"edge\","
                        "\"Timestamp\":%ld,"
                        "\"FromUUID\":\"%s\", "
                        "\"ToUUID\":\"%s\", "
                        "\"EventName\":\"CLONE\", "
                        "\"SyscallID\":%d"
                        "}\n",
            timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id
            );

            
            break;
        }
        case __NR_execve:
        {
            process_node *proc = find_process(e->info.pid);
            if(proc==NULL){
                proc = add_process(e->info.pid);
                if (get_process_cwd(e->info.pid, proc->pwd, sizeof(proc->pwd))!=0){
                    proc->pwd[0] = '\0';// means tracking pwd failed
                }
                uuid_unparse(proc->uuid, uuid_str_to);
                fprintf(tracker_output_file, "{"
                            "\"LogType\":\"node\","
                            "\"UUID\":\"%s\", "
                            "\"NodeName\":\"%s\", "
                            "\"NodeType\":\"process\", "
                            "\"ProcessID\":%d, "
                            "\"ThreadID\":%d"
                            "}\n",
                uuid_str_to, e->info.comm, e->info.pid,e->info.tgid
                );
            }

            execute_cloexec(proc);
            
            if(e->args.execve.pathname[0] != '/'){
                join_and_normalize_path(proc->pwd,e->args.execve.pathname,absolute_path);
            }
            else{
                strcpy(absolute_path,e->args.execve.pathname);
            }
            uuid_unparse(proc->uuid, uuid_str_to);
            get_uuid_fd_unparse(absolute_path, FD_FILE, uuid_str_from);
            fprintf(tracker_output_file, "{"
                        "\"LogType\":\"edge\","
                        "\"Timestamp\":%ld,"
                        "\"FromUUID\":\"%s\", "
                        "\"ToUUID\":\"%s\", "
                        "\"EventName\":\"EXECVE\", "
                        "\"SyscallID\":%d, "
                        "\"FromName\":\"%s\""
                        "}\n",
            timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, absolute_path
            );
            break;
        }
        case __NR_chdir:
        {
            process_node *proc = find_process(e->info.pid);
            if(proc==NULL){
                proc = add_process(e->info.pid);
                if (get_process_cwd(e->info.pid, proc->pwd, sizeof(proc->pwd))!=0){
                    proc->pwd[0] = '\0';// means tracking pwd failed
                }
                uuid_unparse(proc->uuid, uuid_str_to);
                fprintf(tracker_output_file, "{"
                            "\"LogType\":\"node\","
                            "\"UUID\":\"%s\", "
                            "\"NodeName\":\"%s\", "
                            "\"NodeType\":\"process\", "
                            "\"ProcessID\":%d, "
                            "\"ThreadID\":%d"
                            "}\n",
                uuid_str_to, e->info.comm, e->info.pid,e->info.tgid
                );
            }
            else{
                if(e->args.chdir.pathname[0] == '/'){// absolute path
                    strcpy(proc->pwd,e->args.chdir.pathname);
                }
                else if(proc->pwd[0] != '\0'){// relative path
                    join_and_normalize_path(proc->pwd,e->args.chdir.pathname,absolute_path);
                    strcpy(proc->pwd,absolute_path);
                }
                else if(get_process_cwd(e->info.pid, proc->pwd, sizeof(proc->pwd))!=0){
                    proc->pwd[0] = '\0';// means tracking pwd failed
                }
            }
            break;
        }
        case __NR_fchdir:
        {
            process_node *proc = find_process(e->info.pid);
            if(proc==NULL){
                proc = add_process(e->info.pid);
                if (get_process_cwd(e->info.pid, proc->pwd, sizeof(proc->pwd))!=0){
                    proc->pwd[0] = '\0';// means tracking pwd failed
                }
                uuid_unparse(proc->uuid, uuid_str_to);
                fprintf(tracker_output_file, "{"
                            "\"LogType\":\"node\","
                            "\"UUID\":\"%s\", "
                            "\"NodeName\":\"%s\", "
                            "\"NodeType\":\"process\", "
                            "\"ProcessID\":%d, "
                            "\"ThreadID\":%d"
                            "}\n",
                uuid_str_to, e->info.comm, e->info.pid,e->info.tgid
                );
            }
            else{
                fd_node *fd = find_fd(proc,e->args.fchdir.fd);
                if (fd != NULL && fd->name[0] != '\0'){
                    strcpy(proc->pwd,fd->name);
                }
                else if (get_process_cwd(e->info.pid, proc->pwd, sizeof(proc->pwd))!=0){
                    proc->pwd[0] = '\0';// means tracking pwd failed
                }
            }
            break;
        }
        case __NR_ptrace:
        {
            process_node *proc = find_process(e->info.pid);
            if(proc==NULL){
                proc = add_process(e->info.pid);
                if (get_process_cwd(e->info.pid, proc->pwd, sizeof(proc->pwd))!=0){
                    proc->pwd[0] = '\0';// means tracking pwd failed
                }
                uuid_unparse(proc->uuid, uuid_str_to);
                fprintf(tracker_output_file, "{"
                            "\"LogType\":\"node\","
                            "\"UUID\":\"%s\", "
                            "\"NodeName\":\"%s\", "
                            "\"NodeType\":\"process\", "
                            "\"ProcessID\":%d, "
                            "\"ThreadID\":%d"
                            "}\n",
                uuid_str_to, e->info.comm, e->info.pid,e->info.tgid
                );
            }
            else{
                process_node *ptrace_proc = find_process(e->args.ptrace.pid);
                if(ptrace_proc==NULL){
                    ptrace_proc = add_process(e->args.ptrace.pid);
                }
                uuid_unparse(ptrace_proc->uuid, uuid_str_to);
                uuid_unparse(proc->uuid, uuid_str_from);
                fprintf(tracker_output_file, "{"
                            "\"LogType\":\"edge\","
                            "\"Timestamp\":%ld,"
                            "\"FromUUID\":\"%s\", "
                            "\"ToUUID\":\"%s\", "
                            "\"EventName\":\"PTRACE\", "
                            "\"SyscallID\":%d, "
                            "}\n",
                timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id
                );
            }
            break;
        }
        case __NR_exit:
        case __NR_exit_group:
        {
            delete_process(e->info.pid);
            break;
        }
        case __NR_openat:
        case __NR_open:
        case __NR_creat:
        case __NR_dup:
        case __NR_dup2:
        case __NR_dup3:
        case __NR_fcntl:
        case __NR_close:
        case __NR_unlinkat:
        case __NR_unlink:
        case __NR_read:
        case __NR_pread64:
        case __NR_readv:
        case __NR_preadv:
        case __NR_preadv2:
        case __NR_write:
        case __NR_pwrite64:
        case __NR_writev:
        case __NR_pwritev:
        case __NR_pwritev2:
        case __NR_truncate:
        case __NR_ftruncate:
        case __NR_rename:
        case __NR_renameat:
        case __NR_renameat2:
        case __NR_chmod:
        case __NR_fchmodat:
        case __NR_fchmod:
        // case __NR_stat: // High frequency of use, low useful information
        // case __NR_lstat:
        // case __NR_fstat:
        // case __NR_newfstatat:
        // case __NR_statx:
        case __NR_socket:
        case __NR_bind:
        case __NR_listen:
        case __NR_connect:
        case __NR_accept:
        case __NR_accept4:
        case __NR_recvfrom:
        case __NR_recvmsg:
        case __NR_recvmmsg:
        case __NR_sendto:
        case __NR_sendmsg:
        case __NR_sendmmsg:
        case __NR_mmap:
        // case __NR_mprotect:
        case __NR_munmap:
        case __NR_shmget:
        case __NR_shmat:
        // case __NR_shmdt:
        case __NR_shmctl:
        case __NR_msgget:
        case __NR_msgsnd:
        case __NR_msgrcv:
        case __NR_msgctl:
        case __NR_mq_open:
        case __NR_mq_unlink:
        case __NR_mq_timedsend:
        case __NR_mq_timedreceive:
        // case __NR_mq_notify:
        // case __NR_mq_getsetattr:
        case __NR_pipe:
        case __NR_pipe2:
        {
            process_node *proc = find_process(e->info.pid);
            if(proc==NULL){
                proc = add_process(e->info.pid);
                if (get_process_cwd(e->info.pid, proc->pwd, sizeof(proc->pwd))!=0){
                    proc->pwd[0] = '\0';// means tracking pwd failed
                }
                uuid_unparse(proc->uuid, uuid_str_to);
                fprintf(tracker_output_file, "{"
                            "\"LogType\":\"node\","
                            "\"UUID\":\"%s\", "
                            "\"NodeName\":\"%s\", "
                            "\"NodeType\":\"process\", "
                            "\"ProcessID\":%d, "
                            "\"ThreadID\":%d"
                            "}\n",
                uuid_str_to, e->info.comm, e->info.pid,e->info.tgid
                );
            }

            // If return value indicates an error (negative return value) and it's not a special case,
            // break the case to ignore the syscall.
            int is_connect_error = (e->info.syscall_id == __NR_connect && e->info.return_value == -115);
            // 'connect' returns -115 (EINPROGRESS) when the operation is in progress, not a failure.
            int is_mmap_or_shmat = (e->info.syscall_id == __NR_mmap || e->info.syscall_id == __NR_shmat);
            // 'mmap' and 'shmat' return addresses, not error codes, even on failure.
            if (e->info.return_value < 0 && !is_mmap_or_shmat && !is_connect_error) {
                break;
            }

            switch (e->info.syscall_id) {
                case __NR_openat:
                case __NR_open:
                case __NR_creat:
                {
                    fd_node *new_fd = add_fd(proc,e->info.return_value,FD_FILE,!!(e->args.open.flags&O_CLOEXEC));
                    if(e->args.open.pathname[0] != '/'){
                        if(e->args.open.dirfd>0){
                            fd_node *fd = find_fd(proc, e->args.open.dirfd);
                            if(fd != NULL && fd->name[0] != '\0'){
                                join_and_normalize_path(fd->name,e->args.open.pathname,new_fd->name);
                            }
                            else{
                                strcpy(new_fd->name,e->args.open.pathname);
                            }
                        }
                        else{
                            join_and_normalize_path(proc->pwd,e->args.open.pathname,new_fd->name);
                        }
                    }
                    else{
                        strcpy(new_fd->name,e->args.open.pathname);
                    }
                    
                    uuid_unparse(proc->uuid, uuid_str_to);
                    get_uuid_fd_unparse(new_fd->name,new_fd->type,uuid_str_from);
                    int mode = e->args.open.flags & O_ACCMODE;
                    if(mode == O_RDONLY ||mode == O_RDWR){
                        fprintf(tracker_output_file, "{"
                                    "\"LogType\":\"edge\","
                                    "\"Timestamp\":%ld,"
                                    "\"FromUUID\":\"%s\", "
                                    "\"ToUUID\":\"%s\", "
                                    "\"EventName\":\"OPEN\", "
                                    "\"SyscallID\":%d, "
                                    "\"FromName\":\"%s\""
                                    "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, new_fd->name
                        );
                    }
                    if(mode == O_WRONLY ||mode == O_RDWR){
                        fprintf(tracker_output_file, "{"
                                    "\"LogType\":\"edge\","
                                    "\"Timestamp\":%ld,"
                                    "\"FromUUID\":\"%s\", "
                                    "\"ToUUID\":\"%s\", "
                                    "\"EventName\":\"OPEN\", "
                                    "\"SyscallID\":%d, "
                                    "\"FromName\":\"%s\""
                                    "}\n",
                        timestamp, uuid_str_to, uuid_str_from, e->info.syscall_id, new_fd->name
                        );
                    }
                    
                    break;
                }
                case __NR_dup:
                case __NR_dup2:
                case __NR_dup3:
                {
                    fd_node *old_fd = find_fd(proc,e->args.dup.oldfd);
                    if(old_fd == NULL){
                        // get_process_fd_info is not guaranteed to get fdinfo
                        if(get_process_fd_info(proc,e->args.dup.oldfd) < 0){
                            get_process_fd_info(proc,e->info.return_value);
                            break;
                        }
                        old_fd = find_fd(proc,e->args.dup.oldfd);
                    }
                    fd_node *new_fd = add_fd(proc,e->info.return_value,old_fd->type,old_fd->is_cloexec);
                    if(e->args.dup.flags != 0){
                        new_fd->is_cloexec = e->args.dup.flags;
                    }
                    strcpy(new_fd->name,old_fd->name);
                    break;
                }
                case __NR_fcntl:
                {
                    if(e->info.return_value<0){
                        break;
                    }
                    fd_node *fd = find_fd(proc,e->args.fcntl.fd);
                    if(fd == NULL){
                        if(get_process_fd_info(proc,e->args.fcntl.fd) < 0){
                            break;
                        }
                        fd = find_fd(proc,e->args.fcntl.fd);
                    }
                    if(e->args.fcntl.cmd == F_SETFD){
                        if(e->args.fcntl.args & FD_CLOEXEC){
                            fd->is_cloexec = 1;
                        }
                        else{
                            fd->is_cloexec = 0;
                        }

                    }
                    // why not use dup()?
                    if(e->args.fcntl.cmd == F_DUPFD){
                        fd_node *new_fd = add_fd(proc, e->info.return_value, fd->type,0);
                        strcpy(new_fd->name,fd->name);
                    }
                    if(e->args.fcntl.cmd == F_DUPFD_CLOEXEC){
                        fd_node *new_fd = add_fd(proc, e->info.return_value, fd->type,1);
                        strcpy(new_fd->name,fd->name);
                    }
                    break;
                }
                case __NR_close:
                {
                    delete_fd(proc,e->args.close.fd);
                    break;
                }
                case __NR_unlinkat:
                case __NR_unlink:
                {
                    if(e->args.unlink.pathname[0] != '/'){
                        if(e->args.unlink.dirfd>0){
                            fd_node *fd = find_fd(proc, e->args.unlink.dirfd);
                            if(fd != NULL && fd->name[0] != '\0'){
                                join_and_normalize_path(fd->name,e->args.unlink.pathname,absolute_path);
                            }
                            else{
                                strcpy(absolute_path,e->args.unlink.pathname);
                            }
                        }
                        else{
                            join_and_normalize_path(proc->pwd,e->args.unlink.pathname,absolute_path);
                        }
                    }
                    else{
                        strcpy(absolute_path,e->args.unlink.pathname);
                    }

                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_fd_unparse(absolute_path,FD_FILE,uuid_str_to);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"UNLINK\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"%s\""
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, absolute_path
                    );
                    break;
                }
                case __NR_read:
                case __NR_pread64:
                case __NR_readv:
                case __NR_preadv:
                case __NR_preadv2:
                {
                    fd_node *fd = find_fd(proc,e->args.fcntl.fd);
                    if(fd == NULL){
                        if(get_process_fd_info(proc,e->args.fcntl.fd) < 0){
                            break;
                        }
                        fd = find_fd(proc,e->args.fcntl.fd);
                    }

                    fd->read_count+=1;
                    fd->read_bytes+=e->info.return_value;

                    if(fd->type & FD_SOCKET && fd->type & FD_SOCKET_SERVER){
                        get_uuid_fd_unparse(fd->name,fd->type, uuid_str_from);
                        get_uuid_fd_unparse(fd->bindname,fd->type,uuid_str_to);
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"READ\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"%s\", "
                                "\"ToName\":\"%s\""
                                "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->name, fd->bindname
                        );
                        break;
                    }

                    get_uuid_fd_unparse(fd->name,fd->type,uuid_str_from);
                    uuid_unparse(proc->uuid, uuid_str_to);
                    
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"READ\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"%s\", "
                                "\"ReadCountTotal\":%ld, "
                                "\"ReadBytesTotal\":%ld"
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->name, 
                    fd->read_count, fd->read_bytes
                    );
                    break;
                }
                case __NR_write:
                case __NR_pwrite64:
                case __NR_writev:
                case __NR_pwritev:
                case __NR_pwritev2:
                {
                    fd_node *fd = find_fd(proc,e->args.fcntl.fd);
                    if(fd == NULL){
                        if(get_process_fd_info(proc,e->args.fcntl.fd) < 0){
                            break;
                        }
                        fd = find_fd(proc,e->args.fcntl.fd);
                    }

                    fd->write_count+=1;
                    fd->write_bytes+=e->info.return_value;

                    if(fd->type & FD_SOCKET && fd->type & FD_SOCKET_SERVER){
                        get_uuid_fd_unparse(fd->bindname,fd->type,uuid_str_from);
                        get_uuid_fd_unparse(fd->name,fd->type, uuid_str_to);
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"WRITE\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"%s\", "
                                "\"ToName\":\"%s\""
                                "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->bindname ,fd->name
                        );
                        break;
                    }

                    get_uuid_fd_unparse(fd->name,fd->type,uuid_str_to);
                    uuid_unparse(proc->uuid, uuid_str_from);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"WRITE\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"%s\", "
                                "\"WriteCountTotal\":%ld, "
                                "\"WriteBytesTotal\":%ld"
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->name, 
                    fd->write_count, fd->write_bytes
                    );
                    break;
                }
                case __NR_truncate:
                {
                    if(e->args.truncate.pathname[0] != '/'){
                        join_and_normalize_path(proc->pwd,e->args.unlink.pathname,absolute_path);
                    }
                    else{
                        strcpy(absolute_path,e->args.truncate.pathname);
                    }

                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_fd_unparse(absolute_path,FD_FILE,uuid_str_to);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"TRUNCATE\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"%s\""
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, absolute_path
                    );
                    break;
                }
                case __NR_ftruncate:
                {
                    fd_node *fd = find_fd(proc,e->args.fcntl.fd);
                    if(fd == NULL){
                        if(get_process_fd_info(proc,e->args.fcntl.fd) < 0){
                            break;
                        }
                        fd = find_fd(proc,e->args.fcntl.fd);
                    }

                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_fd_unparse(fd->name,fd->type,uuid_str_to);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"FTRUNCATE\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"%s\""
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->name
                    );
                    break;
                }
                case __NR_rename:
                case __NR_renameat:
                case __NR_renameat2: //TODO: special flag like RENAME_EXCHANGE
                {
                    fd_node *fd;
                    if(e->args.rename.oldpath[0] != '/'){
                        if(e->args.rename.olddirfd>0){
                            fd = find_fd(proc, e->args.rename.olddirfd);
                            if(fd != NULL && fd->name[0] != '\0'){
                                join_and_normalize_path(fd->name,e->args.rename.oldpath,absolute_path);
                            }
                            else{
                                strcpy(absolute_path,e->args.rename.oldpath);
                            }
                        }
                        else{
                            join_and_normalize_path(proc->pwd,e->args.rename.oldpath,absolute_path);
                        }
                    }
                    else{
                        strcpy(absolute_path,e->args.rename.oldpath);
                    }

                    if(e->args.rename.newpath[0] != '/'){
                        if(e->args.rename.newdirfd>0){
                            fd = find_fd(proc, e->args.rename.newdirfd);
                            if(fd != NULL && fd->name[0] != '\0'){
                                join_and_normalize_path(fd->name,e->args.rename.newpath,absolute_path2);
                            }
                            else{
                                strcpy(absolute_path2,e->args.rename.newpath);
                            }
                        }
                        else{
                            join_and_normalize_path(proc->pwd,e->args.rename.newpath,absolute_path2);
                        }
                    }
                    else{
                        strcpy(absolute_path2,e->args.rename.newpath);
                    }

                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_fd_unparse(absolute_path2,FD_FILE,uuid_str_to);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"RENAME\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"%s\""
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, absolute_path2
                    );
                    get_uuid_fd_unparse(absolute_path,FD_FILE,uuid_str_from);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"RENAME\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"%s\", "
                                "\"ToName\":\"%s\""
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, absolute_path, absolute_path2
                    );

                    break;
                }
                case __NR_chmod:
                case __NR_fchmodat:
                {
                    if(e->args.chmod.pathname[0] != '/'){
                        if(e->args.chmod.dirfd>0){
                            fd_node *fd = find_fd(proc, e->args.chmod.dirfd);
                            if(fd != NULL && fd->name[0] != '\0'){
                                join_and_normalize_path(fd->name,e->args.chmod.pathname,absolute_path);
                            }
                            else{
                                strcpy(absolute_path,e->args.chmod.pathname);
                            }
                        }
                        else{
                            join_and_normalize_path(proc->pwd,e->args.chmod.pathname,absolute_path);
                        }
                    }
                    else{
                        strcpy(absolute_path,e->args.chmod.pathname);
                    }

                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_fd_unparse(absolute_path,FD_FILE,uuid_str_to);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"CHMOD\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"%s\""
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, absolute_path
                    );
                    break;
                }
                case __NR_fchmod:
                {
                    fd_node *fd = find_fd(proc,e->args.fchmod.fd);
                    if(fd == NULL){
                        if(get_process_fd_info(proc,e->args.fchmod.fd) < 0){
                            break;
                        }
                        fd = find_fd(proc,e->args.fchmod.fd);
                    }

                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_fd_unparse(fd->name,fd->type,uuid_str_to);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"FCHMOD\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"%s\""
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->name
                    );
                    break;
                }

                case __NR_socket:
                {
                    fd_node *fd = add_fd(proc,e->info.return_value,FD_SOCKET,!!(e->args.socket.type&SOCK_CLOEXEC));
                    if(e->args.socket.domain==AF_UNIX){
                        fd->type = fd->type|FD_SOCKET_UNIX;
                    }
                    break;
                }
                case __NR_bind:
                {
                    fd_node *fd = find_fd(proc,e->args.bind.fd);
                    if(fd == NULL){
                        fd = add_fd(proc,e->args.bind.fd, FD_SOCKET | FD_SOCKET_SERVER,1);
                    }
                    else{
                        fd->type = fd->type | FD_SOCKET_SERVER;
                    }
                    
                    
                    sockaddr_parse((struct sockaddr *)&e->args.bind.addr, fd->bindname, sizeof(fd->bindname));
                    struct sockaddr_un *sun_addr = (struct sockaddr_un *)e->args.bind.addr;

                    if (sun_addr->sun_family == AF_UNIX && fd->bindname[0]!='/' && sun_addr->sun_path[0] != '\0' 
                        && fd != NULL){
                        join_and_normalize_path(proc->pwd, fd->bindname, absolute_path);
                        strcpy(fd->bindname,absolute_path);
                    }

                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_fd_unparse(fd->bindname,FD_SOCKET,uuid_str_to);
                    fprintf(tracker_output_file, "{"
                            "\"LogType\":\"edge\","
                            "\"Timestamp\":%ld,"
                            "\"FromUUID\":\"%s\", "
                            "\"ToUUID\":\"%s\", "
                            "\"EventName\":\"BIND\", "
                            "\"SyscallID\":%d, "
                            "\"ToName\":\"%s\""
                            "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->bindname
                    );
                    fprintf(tracker_output_file, "{"
                            "\"LogType\":\"edge\","
                            "\"Timestamp\":%ld,"
                            "\"FromUUID\":\"%s\", "
                            "\"ToUUID\":\"%s\", "
                            "\"EventName\":\"BIND\", "
                            "\"SyscallID\":%d, "
                            "\"FromName\":\"%s\""
                            "}\n",
                    timestamp, uuid_str_to, uuid_str_from, e->info.syscall_id, fd->bindname
                    );
                    break;
                }
                case __NR_listen:
                {
                    fd_node *fd = find_fd(proc,e->args.connect.fd);
                    if(fd == NULL){
                        fd = add_fd(proc,e->args.connect.fd,FD_SOCKET|FD_SOCKET_LISTEN,1);
                    }
                    else{
                        fd->type = (fd->type & FD_SOCKET_STATUS_MASK)|FD_SOCKET_LISTEN;
                    }
                    break;
                }
                case __NR_connect:
                {
                    fd_node *fd = find_fd(proc,e->args.connect.fd);
                    if(fd == NULL){
                        fd = add_fd(proc,e->args.connect.fd,FD_SOCKET|FD_SOCKET_ESTAB,1);
                    }
                    else{
                        fd->type =  (fd->type & FD_SOCKET_STATUS_MASK)|FD_SOCKET_ESTAB;
                    }

                    sockaddr_parse((struct sockaddr *)&e->args.connect.addr, fd->name, sizeof(fd->name));
                    struct sockaddr_un *sun_addr = (struct sockaddr_un *)e->args.connect.addr;

                    if (sun_addr->sun_family == AF_UNIX && fd->name[0]!='/' && sun_addr->sun_path[0] != '\0' 
                        && fd != NULL){
                        join_and_normalize_path(proc->pwd, fd->name, absolute_path);
                        strcpy(fd->name,absolute_path);
                    }

                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_fd_unparse(fd->name,fd->type,uuid_str_to);
                    fprintf(tracker_output_file, "{"
                            "\"LogType\":\"edge\","
                            "\"Timestamp\":%ld,"
                            "\"FromUUID\":\"%s\", "
                            "\"ToUUID\":\"%s\", "
                            "\"EventName\":\"CONNECT\", "
                            "\"SyscallID\":%d, "
                            "\"ToName\":\"%s\""
                            "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->name
                    );
                    break;
                }
                case __NR_accept:
                case __NR_accept4:
                {
                    fd_node *socket_fd = find_fd(proc,e->args.accept.fd);
                    if(socket_fd == NULL){
                        socket_fd = add_fd(proc,e->args.accept.fd,FD_SOCKET|FD_SOCKET_LISTEN,1);
                    }

                    fd_node *fd = add_fd(proc,e->info.return_value,FD_SOCKET|FD_SOCKET_ESTAB,e->args.accept.flags&SOCK_CLOEXEC);
                    if(socket_fd->type&FD_SOCKET_UNIX){
                        fd->type = fd->type|FD_SOCKET_UNIX|FD_SOCKET_SERVER;
                        break;
                        //no output for 2 reasons:
                        //1. the UNIX domain usually does not have a client address.
                        //2. server's accept() and client's connect() are duplicate records.
                    }

                    sockaddr_parse((struct sockaddr *)&e->args.connect.addr, fd->name, sizeof(fd->name));
                    struct sockaddr_un *sun_addr = (struct sockaddr_un *)e->args.accept.addr;

                    if (sun_addr->sun_family == AF_UNIX && fd->name[0]!='/' && sun_addr->sun_path[0] != '\0' 
                        && fd != NULL){
                        join_and_normalize_path(proc->pwd, fd->name, absolute_path);
                        strcpy(fd->name,absolute_path);
                    }

                    get_uuid_fd_unparse(fd->name, fd->type, uuid_str_from);
                    get_uuid_fd_unparse(socket_fd->bindname,FD_SOCKET, uuid_str_to);
                    fprintf(tracker_output_file, "{"
                            "\"LogType\":\"edge\","
                            "\"Timestamp\":%ld,"
                            "\"FromUUID\":\"%s\", "
                            "\"ToUUID\":\"%s\", "
                            "\"EventName\":\"ACCEPT\", "
                            "\"SyscallID\":%d, "
                            "\"FromName\":\"%s\", "
                            "\"ToName\":\"%s\""
                            "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->name, socket_fd->bindname
                    );
                    break;
                }
                case __NR_recvfrom:
                {
                    fd_node *fd = find_fd(proc,e->args.recv.fd);
                    if(fd == NULL){
                        // fd = add_fd(proc,e->args.recv.fd,FD_SOCKET,1);
                        break;
                    }

                    if((fd->type & FD_SOCKET_UNIX) && (fd->type & FD_SOCKET_SERVER)){
                        break;
                        //no output for duplicate records.(only record client recv/send)
                    }

                    if(fd->type&FD_SOCKET_ESTAB || e->args.recv.addrptr==NULL){
                        strcpy(absolute_path,fd->name);
                    }
                    else{
                        sockaddr_parse((struct sockaddr *)&e->args.recv.addr, absolute_path, sizeof(absolute_path));
                        struct sockaddr_un *sun_addr = (struct sockaddr_un *)e->args.recv.addr;

                        if (sun_addr->sun_family == AF_UNIX && fd->name[0]!='/' && sun_addr->sun_path[0] != '\0' 
                            && fd != NULL){
                            join_and_normalize_path(proc->pwd, absolute_path, absolute_path2);
                            strcpy(absolute_path,absolute_path2);
                        }
                    }

                    if(fd->type & FD_SOCKET_SERVER){
                        get_uuid_fd_unparse(absolute_path, FD_SOCKET,uuid_str_from);
                        get_uuid_fd_unparse(fd->bindname,FD_SOCKET,uuid_str_to);
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"RECVFROM\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"%s\", "
                                "\"ToName\":\"%s\""
                                "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, absolute_path, fd->bindname
                        );
                    }
                    else{
                        get_uuid_fd_unparse(absolute_path, FD_SOCKET,uuid_str_from);
                        uuid_unparse(proc->uuid, uuid_str_to);
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"RECVFROM\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"%s\""
                                "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, absolute_path
                        );
                    }
                    break;
                }
                case __NR_recvmsg:
                case __NR_recvmmsg:
                {
                    fd_node *fd = find_fd(proc,e->args.recv.fd);
                    if(fd == NULL){
                        // fd = add_fd(proc,e->args.recv.fd,FD_SOCKET|FD_SOCKET_ESTAB,1);
                        break;
                    }

                    if((fd->type & FD_SOCKET_UNIX) && (fd->type & FD_SOCKET_SERVER)){
                        break;
                        //no output for duplicate records.(only record client recv/send)
                    }

                    if(fd->type & FD_SOCKET_SERVER){
                        get_uuid_fd_unparse(fd->name, fd->type,uuid_str_from);
                        get_uuid_fd_unparse(fd->bindname,FD_SOCKET,uuid_str_to);
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"RECV\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"%s\", "
                                "\"ToName\":\"%s\""
                                "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->name, fd->bindname
                        );
                    }
                    else{
                        get_uuid_fd_unparse(fd->name, fd->type,uuid_str_from);
                        uuid_unparse(proc->uuid, uuid_str_to);
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"RECV\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"%s\""
                                "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->name
                        );
                    }
                    break;
                }
                case __NR_sendto:
                {
                    fd_node *fd = find_fd(proc,e->args.send.fd);
                    if(fd == NULL){
                        // fd = add_fd(proc,e->args.send.fd,FD_SOCKET,1);
                        break;
                    }

                    if((fd->type & FD_SOCKET_UNIX) && (fd->type & FD_SOCKET_SERVER)){
                        break;
                        //no output for duplicate records.(only record client recv/send)
                    }

                    if(fd->type&FD_SOCKET_ESTAB || e->args.send.addrptr==NULL){
                        strcpy(absolute_path,fd->name);
                    }
                    else{
                        sockaddr_parse((struct sockaddr *)&e->args.send.addr, absolute_path, sizeof(absolute_path));
                        struct sockaddr_un *sun_addr = (struct sockaddr_un *)e->args.send.addr;

                        if (sun_addr->sun_family == AF_UNIX && fd->name[0]!='/' && sun_addr->sun_path[0] != '\0' 
                            && fd != NULL){
                            join_and_normalize_path(proc->pwd, absolute_path, absolute_path2);
                            strcpy(absolute_path,absolute_path2);
                        }
                    }
                    
                    if(fd->type & FD_SOCKET_SERVER){
                        get_uuid_fd_unparse(fd->bindname, FD_SOCKET,uuid_str_from);
                        get_uuid_fd_unparse(absolute_path,FD_SOCKET,uuid_str_to);
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"SENDTO\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"%s\", "
                                "\"ToName\":\"%s\""
                                "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->bindname, absolute_path
                        );
                    }
                    else{
                        uuid_unparse(proc->uuid, uuid_str_from);
                        get_uuid_fd_unparse(absolute_path,FD_SOCKET,uuid_str_to);
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"SENDTO\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"%s\""
                                "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, absolute_path
                        );
                    }
                    break;
                }
                case __NR_sendmsg:
                case __NR_sendmmsg:
                {
                    fd_node *fd = find_fd(proc,e->args.recv.fd);
                    if(fd == NULL){
                        // fd = add_fd(proc,e->args.recv.fd,FD_SOCKET|FD_SOCKET_ESTAB,1);
                        break;
                    }

                    if((fd->type & FD_SOCKET_UNIX) && (fd->type & FD_SOCKET_SERVER)){
                        break;
                        //no output for duplicate records.(only record client recv/send)
                    }

                    if(fd->type & FD_SOCKET_SERVER){
                        get_uuid_fd_unparse(fd->bindname, FD_SOCKET,uuid_str_from);
                        get_uuid_fd_unparse(fd->name, fd->type,uuid_str_to);
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"SEND\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"%s\", "
                                "\"ToName\":\"%s\""
                                "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->bindname, fd->name
                        );
                    }
                    else{
                        uuid_unparse(proc->uuid, uuid_str_from);
                        get_uuid_fd_unparse(fd->name, fd->type,uuid_str_to);
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"SEND\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"%s\""
                                "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, fd->name
                        );
                    }
                    break;
                }

                case __NR_mmap:
                {
                    if(!(e->args.mmap.flags & MAP_SHARED) || !(e->args.mmap.flags & MAP_ANONYMOUS)){
                        break;
                        // private memory doesn't pass messages between processes.
                        // mmap maps a file that is difficult to record (e.g., only part of the file is mapped) 
                        //and the information has been recorded by open()
                    }
                    fd_node * memory_region = add_fd(proc,(int)e->info.return_value,FD_MEMORY,1);
                    snprintf(memory_region->name, 256, "memory_region-%p", (void *)e->info.return_value);
                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_fd_unparse(memory_region->name, memory_region->type,uuid_str_to);
                    fprintf(tracker_output_file, "{"
                            "\"LogType\":\"edge\","
                            "\"Timestamp\":%ld,"
                            "\"FromUUID\":\"%s\", "
                            "\"ToUUID\":\"%s\", "
                            "\"EventName\":\"MMAP\", "
                            "\"SyscallID\":%d, "
                            "\"ToName\":\"%s\""
                            "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, memory_region->name
                    );
                    fprintf(tracker_output_file, "{"
                            "\"LogType\":\"edge\","
                            "\"Timestamp\":%ld,"
                            "\"FromUUID\":\"%s\", "
                            "\"ToUUID\":\"%s\", "
                            "\"EventName\":\"MMAP\", "
                            "\"SyscallID\":%d, "
                            "\"FromName\":\"%s\""
                            "}\n",
                    timestamp, uuid_str_to, uuid_str_from, e->info.syscall_id, memory_region->name
                    );
                    break;
                }
                // case __NR_mprotect:
                case __NR_munmap:
                {
                    delete_fd(proc,(int)e->info.return_value);
                    break;
                }

                case __NR_shmget:
                {
                    if(e->args.shmget.shmflg&IPC_CREAT){
                        add_shm(e->info.return_value);
                    }
                    break;
                }
                case __NR_shmat:
                {
                    shm_node *shm = find_shm(e->args.shmat.shmid);
                    uuid_unparse(proc->uuid, uuid_str_to);
                    uuid_unparse(shm->uuid, uuid_str_from);
                    fprintf(tracker_output_file, "{"
                            "\"LogType\":\"edge\","
                            "\"Timestamp\":%ld,"
                            "\"FromUUID\":\"%s\", "
                            "\"ToUUID\":\"%s\", "
                            "\"EventName\":\"SHMAT\", "
                            "\"SyscallID\":%d, "
                            "\"FromName\":\"SHM%d\""
                            "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, shm->shmid
                    );
                    if(!(e->args.shmat.shmflg&SHM_RDONLY)){
                        fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"SHMAT\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"SHM%d\""
                                "}\n",
                        timestamp, uuid_str_to, uuid_str_from, e->info.syscall_id, shm->shmid
                        );
                    }
                    break;
                }
                // case __NR_shmdt: // do nothing
                case __NR_shmctl:
                {
                    if(e->args.shmctl.cmd == IPC_RMID){
                        delete_shm(e->args.shmctl.shmid);
                    }
                    break;
                }

                case __NR_msgget:
                {
                    if(e->args.msgget.msgflg&IPC_CREAT){
                        add_msq(e->info.return_value);
                    }
                    break;
                }
                case __NR_msgsnd:
                {
                    msq_node *msq = find_msq(e->args.msgsnd.msqid);
                    uuid_unparse(proc->uuid, uuid_str_from);
                    uuid_unparse(msq->uuid, uuid_str_to);
                    fprintf(tracker_output_file, "{"
                            "\"LogType\":\"edge\","
                            "\"Timestamp\":%ld,"
                            "\"FromUUID\":\"%s\", "
                            "\"ToUUID\":\"%s\", "
                            "\"EventName\":\"MSGSND\", "
                            "\"SyscallID\":%d, "
                            "\"ToName\":\"MSQ%d\""
                            "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, msq->msqid
                    );
                    break;
                }
                case __NR_msgrcv:
                {
                    msq_node *msq = find_msq(e->args.msgsnd.msqid);
                    uuid_unparse(proc->uuid, uuid_str_to);
                    uuid_unparse(msq->uuid, uuid_str_from);
                    fprintf(tracker_output_file, "{"
                            "\"LogType\":\"edge\","
                            "\"Timestamp\":%ld,"
                            "\"FromUUID\":\"%s\", "
                            "\"ToUUID\":\"%s\", "
                            "\"EventName\":\"MSGRCV\", "
                            "\"SyscallID\":%d, "
                            "\"FromName\":\"MSQ%d\""
                            "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, msq->msqid
                    );
                    break;
                }
                case __NR_msgctl:
                {
                    if(e->args.msgctl.op == IPC_RMID){
                        delete_shm(e->args.msgctl.msqid);
                    }
                    break;
                }

                case __NR_mq_open:
                {
                    mq_node *mq=add_mq(e->info.return_value);
                    strcpy(mq->name,e->args.mqopen.name);

                    uuid_unparse(proc->uuid, uuid_str_to);
                    get_uuid_mq_unparse(mq->name,uuid_str_from);
                    int mode = e->args.mqopen.oflag & O_ACCMODE;
                    if(mode == O_RDONLY ||mode == O_RDWR){
                        fprintf(tracker_output_file, "{"
                                    "\"LogType\":\"edge\","
                                    "\"Timestamp\":%ld,"
                                    "\"FromUUID\":\"%s\", "
                                    "\"ToUUID\":\"%s\", "
                                    "\"EventName\":\"MQ_OPEN\", "
                                    "\"SyscallID\":%d, "
                                    "\"FromName\":\"MQ/%s\""
                                    "}\n",
                        timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, mq->name
                        );
                    }
                    if(mode == O_WRONLY ||mode == O_RDWR){
                        fprintf(tracker_output_file, "{"
                                    "\"LogType\":\"edge\","
                                    "\"Timestamp\":%ld,"
                                    "\"FromUUID\":\"%s\", "
                                    "\"ToUUID\":\"%s\", "
                                    "\"EventName\":\"MQ_OPEN\", "
                                    "\"SyscallID\":%d, "
                                    "\"ToName\":\"MQ/%s\""
                                    "}\n",
                        timestamp, uuid_str_to, uuid_str_from, e->info.syscall_id, mq->name
                        );
                    }
                    break;
                }
                case __NR_mq_unlink:
                {
                    delete_mq(e->args.mqunlink.name);
                    break;
                }
                case __NR_mq_timedsend:
                {
                    mq_node *mq=find_mq(e->info.return_value);
                    if(mq == NULL){
                        break;
                    }
                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_mq_unparse(mq->name, uuid_str_to);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"MQ_TIMEDSEND\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"MQ/%s\""
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, mq->name
                    );
                    break;
                }
                case __NR_mq_timedreceive:
                {
                    mq_node *mq=find_mq(e->info.return_value);
                    if(mq == NULL){
                        break;
                    }
                    uuid_unparse(proc->uuid, uuid_str_to);
                    get_uuid_mq_unparse(mq->name, uuid_str_from);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"MQ_TIMEDRECEIVE\", "
                                "\"SyscallID\":%d, "
                                "\"FromName\":\"MQ/%s\""
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, mq->name
                    );
                    break;
                }
                // case __NR_mq_notify:
                // case __NR_mq_getsetattr:

                case __NR_pipe:
                case __NR_pipe2:
                {
                    fd_node *in_fd = add_fd(proc,e->args.pipe.fd_in,FD_PIPE,!!(e->args.pipe.flags&O_CLOEXEC));
                    fd_node *out_fd = add_fd(proc,e->args.pipe.fd_out,FD_PIPE,!!(e->args.pipe.flags&O_CLOEXEC));
                    
                    snprintf(in_fd->name, 256, "pipe-%d-%d-%d-%lx", e->info.pid, e->args.pipe.fd_in, e->args.pipe.fd_out,timestamp& 0xFFFF);
                    strcpy(out_fd->name, in_fd->name);

                    uuid_unparse(proc->uuid, uuid_str_from);
                    get_uuid_fd_unparse(in_fd->name, in_fd->type,uuid_str_to);
                    fprintf(tracker_output_file, "{"
                                "\"LogType\":\"edge\","
                                "\"Timestamp\":%ld,"
                                "\"FromUUID\":\"%s\", "
                                "\"ToUUID\":\"%s\", "
                                "\"EventName\":\"PIPE\", "
                                "\"SyscallID\":%d, "
                                "\"ToName\":\"%s\""
                                "}\n",
                    timestamp, uuid_str_from, uuid_str_to, e->info.syscall_id, in_fd->name
                    );
                    break;
                }
            }

            break;
        }
    }
}

void cleanup_tracker(){
    // print_all_processes();
    if (tracker_output_file) {
        fflush(tracker_output_file);
        fclose(tracker_output_file);
        printf("tracker_output_file safely closed\n");
        tracker_output_file = NULL;
    }
}