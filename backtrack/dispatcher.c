#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <pthread.h>
#include <semaphore.h>
#include "catcher.skel.h"
#include "syscall_event.h"
#include "tracker.h"
#include "recorder.h"
#include "config.h"

volatile sig_atomic_t exiting = 0;
time_t boot_timestamp = 0;

typedef struct {
    struct Event queue[WORKER_QUEUE_SIZE];
    int head, tail, drop_counter;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} TaskQueue;

typedef struct {
    int id;
    sem_t sem;
    TaskQueue *task_queue;
} WorkerArgs;

TaskQueue task_queues[WORKER_COUNT];
pthread_t worker_threads[WORKER_COUNT];
WorkerArgs worker_args[WORKER_COUNT];


void sig_handler(int signo) {
    if (exiting == 0) {
        exiting = 1;
        printf("Caught SIGINT (Ctrl-C), Waiting to finish caching events...\n");
    } else if (exiting == 1) {
        exiting = 2;
        printf("Caught SIGINT again, Cache events forcibly dropped...\n");
    }
    else{
        printf("Caught SIGINT too many times, force exiting now!\n");
        kill(0, SIGTERM);
    }
}

typedef struct {
    unsigned char bitmap[MAX_PIDS / 8];
} pid_bitmap_t;
pid_bitmap_t bitmap;
pthread_mutex_t bitmap_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef ENABLE_TRACKER
void init_pid_bitmap() {
    memset(bitmap.bitmap, 0, sizeof(bitmap.bitmap));
}

void set_pid_block(int pid) {
    if (pid >= 0 && pid < MAX_PIDS) {
        pthread_mutex_lock(&bitmap_lock);
        bitmap.bitmap[pid / 8] |= (1 << (pid % 8));
        pthread_mutex_unlock(&bitmap_lock);
        // printf("block PID: %d\n", pid);
    } else {
        // printf("Invalid PID: %d\n", pid);
    }
}

void set_pid_proceed(int pid) {
    if (pid >= 0 && pid < MAX_PIDS) {
        pthread_mutex_lock(&bitmap_lock);
        bitmap.bitmap[pid / 8] &= ~(1 << (pid % 8));
        pthread_mutex_unlock(&bitmap_lock);
        sem_post(&worker_args[pid % WORKER_COUNT].sem);
        // printf("proceed PID: %d\n", pid);
    } else {
        printf("Invalid PID: %d\n", pid);
    }
}

int is_pid_block(int pid) {
    if (pid >= 0 && pid < MAX_PIDS) {
        pthread_mutex_lock(&bitmap_lock);
        int result = (bitmap.bitmap[pid / 8] & (1 << (pid % 8))) != 0;
        pthread_mutex_unlock(&bitmap_lock);
        return result;
    } else {
        printf("Invalid PID: %d\n", pid);
        return 0;
    }
}
#endif /* ENABLE_TRACKER */ 

static int handle_file_event(void *data) {
    // struct timeval tv;
    // gettimeofday(&tv, NULL);
    // long timestamp =  tv.tv_sec*1000000 + tv.tv_usec;

    const struct Event *e = (struct Event *) data;

    long timestamp = boot_timestamp*1000000 + e->info.timestamp;

    #ifdef ENABLE_TRACKER
    update_tracker(timestamp, data);
    #endif /* ENABLE_TRACKER */

    #ifdef ENABLE_RECORDER
    update_recorder(timestamp, data);
    #endif /* ENABLE_RECORDER */
    
    return 0;
}

void task_queue_init(TaskQueue *queue) {
    queue->head = 0;
    queue->tail = 0;
    queue->drop_counter = 0;
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->cond, NULL);
}

bool task_queue_push(TaskQueue *queue, const struct Event *event) {
    
    pthread_mutex_lock(&queue->lock);
    int next = (queue->tail + 1) % WORKER_QUEUE_SIZE;
    // printf("push to queue info: tail:%d, next:%d, head:%d\n", queue->tail, next, queue->head);
    if (next == queue->head) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }
    queue->queue[queue->tail] = *event;
    queue->tail = next;
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->lock);
    return true;
}

// Uses 'queue->cond' to wait when the task queue is empty.
// Uses 'worker->sem' to ensure syscalls execute after 'clone' (if captured 'clone').
void *worker_function(void *arg) {
    WorkerArgs *worker = (WorkerArgs *)arg;
    TaskQueue *queue = worker->task_queue;
    struct Event *e;

    printf("Worker %d started\n", worker->id);

    while (exiting<2) {
        pthread_mutex_lock(&queue->lock);
        while (queue->head == queue->tail) {
            if (exiting) {
                pthread_mutex_unlock(&queue->lock);
                return NULL;
            }
            pthread_cond_wait(&queue->cond, &queue->lock);
        }
        e = &queue->queue[queue->head];
        pthread_mutex_unlock(&queue->lock);

        #ifdef ENABLE_TRACKER
        if (is_pid_block(e->info.pid)) {
            // printf("waiting for PID: %d\n", e->info.pid);
            sem_wait(&worker->sem);
        }
        #endif /* ENABLE_TRACKER */

        handle_file_event(e);

        #ifdef ENABLE_TRACKER
        if (e->info.syscall_id == __NR_clone || e->info.syscall_id == __NR_clone3){
            if(e->info.return_value>=0){
                set_pid_proceed(e->info.return_value);
                // printf("queue status, head:%d, tail:%d\n",queue->head,queue->tail);
            }
        }
        #endif /* ENABLE_TRACKER */

        pthread_mutex_lock(&queue->lock);
        queue->head = (queue->head + 1) % WORKER_QUEUE_SIZE;
        pthread_mutex_unlock(&queue->lock);
    }

    printf("Worker %d exiting\n", worker->id);
    return NULL;
}

int handle_rb_event(void *ctx, void *data, size_t data_sz) {
    const struct Event *e = (struct Event *) data;
    int select_queue = e->info.pid % WORKER_COUNT;

    #ifdef ENABLE_TRACKER
    if (e->info.syscall_id == __NR_clone || e->info.syscall_id == __NR_clone3){
        if(e->info.return_value>=0){
            set_pid_block(e->info.return_value);
            // printf("queue %d status, head:%d, tail:%d\n",select_queue,task_queues[select_queue].head,task_queues[select_queue].tail);
        }
    }
    #endif /* ENABLE_TRACKER */

    if (!task_queue_push(&task_queues[select_queue], e)) {
        task_queues[select_queue].drop_counter++;
        // printf("Queue %d is full, dropping event\n", select_queue);

        #ifdef ENABLE_TRACKER
        if (e->info.syscall_id == __NR_clone || e->info.syscall_id == __NR_clone3){
            if(e->info.return_value>=0){
                set_pid_proceed(e->info.return_value);
            }
        }
        #endif /* ENABLE_TRACKER */

        return 0;
    }

    return 0;
}



int main() {
    if (geteuid() != 0) {
        fprintf(stderr, "Error: BackTrack must be run as root.\n");
        exit(EXIT_FAILURE);
    }
    
    #ifdef ENABLE_RECORDER
    init_recorder();
    #endif /* ENABLE_RECORDER */

    #ifdef ENABLE_TRACKER
    init_tracker();
    #endif /* ENABLE_TRACKER */

    //signal(SIGTERM, sig_handler);???
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        perror("Error setting signal handler");
        exit(1);
    }

    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) {
        perror("fopen failed");
        return 1;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "btime %ld", &boot_timestamp) == 1) {
            break;
        }
    }
    fclose(fp);
    if(boot_timestamp==0){
        fprintf(stderr, "get boot timestamp failed\n");
        return 1;
    }
    // printf("boot timestamp:%ld\n",boot_timestamp);

    #ifdef ENABLE_TRACKER
    init_pid_bitmap();
    #endif /* ENABLE_TRACKER */

    for (int i = 0; i < WORKER_COUNT; i++) {
        task_queue_init(&task_queues[i]);
    }
    for (int i = 0; i < WORKER_COUNT; i++) {
        worker_args[i].id = i;
        sem_init(&worker_args[i].sem, 0, 0);
        worker_args[i].task_queue = &task_queues[i];
        pthread_create(&worker_threads[i], NULL, worker_function, &worker_args[i]);
    }
    
    struct ring_buffer *rb = NULL;
    struct catcher_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // libbpf_set_print(libbpf_print_fn);

    /* Load and verify BPF application */
    skel = catcher_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    printf("=========================Open=========================\n");

    /* Load & verify BPF programs */
    err = catcher_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    printf("=========================Load=========================\n");

    /* Attach tracepoints */
    err = catcher_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("=========================Attach=========================\n");

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.event_rb), handle_rb_event ,NULL , NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("=========================Ring Buffer=========================\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 10);
        if (err == -EINTR) {
            err = 0;
            goto cleanup;
            // break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            goto cleanup;
            // break;
        }
    }

    cleanup:

    ring_buffer__free(rb);
    catcher_bpf__destroy(skel);

    for (int i = 0; i < WORKER_COUNT; i++) {
        sem_post(&worker_args[i].sem);
        pthread_cond_signal(&task_queues[i].cond);
        pthread_join(worker_threads[i], NULL);
        printf("queue status, head:%d, tail:%d, drop_counter:%d\n",task_queues[i].head, task_queues[i].tail, task_queues[i].drop_counter);
    }

    #ifdef ENABLE_RECORDER
    cleanup_recorder();
    #endif /* ENABLE_RECORDER */
    #ifdef ENABLE_TRACKER
    cleanup_tracker();
    #endif /* ENABLE_TRACKER */

    return err < 0 ? -err : 0;
}
