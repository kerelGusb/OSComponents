#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>


static volatile sig_atomic_t exiting = 0;

static void handle_sigint(int sig)
{
    (void)sig;
    exiting = 1;
}

static int setup_signals()
{
    struct sigaction sa;

    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;   // NO SA_RESTART

    if (sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1 ||
        sigaction(SIGQUIT, &sa, NULL) == -1)
    {
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <iface>\n", argv[0]);
        return 1;
    }

    if (setup_signals())
    {
        fprintf(stderr, "sigaction\n");
        return 1;
    }

    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;

    const char *iface = argv[1];
    int ifindex = if_nametoindex(iface);

    obj = bpf_object__open_file("xdp_firewall.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) 
    {
        fprintf(stderr, "failed to load bpf object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_firewall");
    if (!prog)
    {
        fprintf(stderr, "failed to find object by name\n");
        return 1;
    }

    link = bpf_program__attach_xdp(prog, ifindex);
    if (!link)
    {
        fprintf(stderr, "attach failed\n");
        return 1;
    }


    printf("XDP firewall attached on %s\n", iface);

    int map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ports");

    __u32 key;
    __u16 port;

    key = 0; port = 22;
    bpf_map_update_elem(map_fd, &key, &port, 0);

    key = 1; port = 80;
    bpf_map_update_elem(map_fd, &key, &port, 0);

    printf("Blocked ports: 22, 80\n");

    while (!exiting)
        pause();

    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}