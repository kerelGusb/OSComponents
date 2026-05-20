#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h> 
#include <sys/stat.h>
#include "event.h"

static volatile sig_atomic_t exiting = 0;

static void handle_sigint(int sig)
{
    (void)sig;
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    (void) ctx;
    (void) len;
    struct event *e = data;

    struct in_addr ip_addr;
    ip_addr.s_addr = e->dest_ip;

    printf("PID=%u COMM=%s DEST=%s:%u\n",
           e->pid, e->comm, inet_ntoa(ip_addr), e->dest_port);
    return 0;
}

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct bpf_map *rb_map;
    int rb_fd;

    struct sigaction sa =
    {
        .sa_handler = handle_sigint
    };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) ||
        sigaction(SIGTERM, &sa, NULL))
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    obj = bpf_object__open_file("lsm_firewall.bpf.o", NULL);
    if (!obj || bpf_object__load(obj))
    {
        fprintf(stderr, "failed to load bpf object\n");
        return 1;
    }

    int block_fd = bpf_object__find_map_fd_by_name(obj, "block_rules");
    if (block_fd >= 0) {
        struct block_key key = {};
        memset(&key, 0, sizeof(key));

        struct stat st;
        if (stat("/usr/bin/curl", &st) == 0) {
            key.ino = st.st_ino;
            key.ip = inet_addr("1.1.1.1");
            
            __u32 val = 1;
            bpf_map_update_elem(block_fd, &key, &val, BPF_ANY);
            printf("Added block rule: /usr/bin/curl (ino: %lu) -> 1.1.1.1\n",
                    key.ino);
        }
    }

    prog = bpf_object__find_program_by_name(obj, "lsm_firewall");
    link = bpf_program__attach(prog);
    if (!link)
    {
        fprintf(stderr, "attach failed\n");
        return 1;
    }

    rb_map = bpf_object__find_map_by_name(obj, "rb");
    rb_fd = bpf_map__fd(rb_map);

    struct ring_buffer *rb =
        ring_buffer__new(rb_fd, handle_event, NULL, NULL);

    if (!rb)
    {
        fprintf(stderr, "ring_buffer__new failed\n");
        return 1;
    }

    printf("Running...\n");

    while (!exiting)
    {
        int ret = ring_buffer__poll(rb, 100);

        if (ret < 0 && errno != EINTR)
        {
            fprintf(stderr, "poll error\n");
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}