#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define MAX_PORTS 16

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u32);
    __type(value, __u16);
} blocked_ports SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 dport = 0;

    void *l4 = (void *)ip + sizeof(struct iphdr);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        dport = __builtin_bswap16(tcp->dest);
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dport = __builtin_bswap16(udp->dest);
    }
    else {
        return XDP_PASS;
    }

    for (__u32 i = 0; i < MAX_PORTS; i++) {
        __u32 key = i;
        __u16 *port = bpf_map_lookup_elem(&blocked_ports, &key);
        if (port && *port == dport) {
            bpf_printk("Blocked port: %d\n", dport);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";