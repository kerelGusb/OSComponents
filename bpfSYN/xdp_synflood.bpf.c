#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32); 
} syn_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} syn_threshold SEC(".maps");

SEC("xdp")
int xdp_synflood(struct xdp_md *ctx)
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!(tcp->syn) || tcp->ack)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    __u32 key0 = 0;
    __u32 *threshold = bpf_map_lookup_elem(&syn_threshold, &key0);
    if (!threshold)
        return XDP_PASS;

    __u32 *count = bpf_map_lookup_elem(&syn_count, &src_ip);

    if (count) {
        (*count)++;

        if (*count > *threshold) {
            bpf_printk("SYN flood from %x\n", src_ip);
            return XDP_DROP;
        }
    } else {
        __u32 init = 1;
        bpf_map_update_elem(&syn_count, &src_ip, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";