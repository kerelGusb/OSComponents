#include "vmlinux.h"
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "event.h"

#define AF_INET 2

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct block_key);
    __type(value, __u32); 
} block_rules SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(lsm_firewall, struct socket *sock, struct sockaddr *address, int addrlen)
{
    (void)sock;
    (void)addrlen;

    if (!address || address->sa_family != AF_INET) return 0;

    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    __u32 dest_ip = addr->sin_addr.s_addr;
    __u16 dest_port = bpf_ntohs(addr->sin_port);

    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        e->pid = pid_tgid >> 32;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->dest_ip = dest_ip;
        e->dest_port = dest_port;
        bpf_ringbuf_submit(e, 0);
    }

    struct block_key key = {};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.ip = dest_ip;

    __u32 *rule = bpf_map_lookup_elem(&block_rules, &key);
    if (rule && *rule == 1) {
        return -EPERM; 
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";