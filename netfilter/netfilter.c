#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/tcp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KDA");
MODULE_DESCRIPTION("my netfilter");

static int dst_port = 0;
module_param(dst_port, int, 0644);
MODULE_PARM_DESC(dst_port, "destination TCP port filter");

static struct nf_hook_ops nfho;

static unsigned int my_netfilter_hook(
        void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);

    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);

    // filtering all packages but those ones 
    // which open connections (SYN and no ACK)
    if (!tcph->syn || tcph->ack)
        return NF_ACCEPT;

    if (dst_port != 0 && ntohs(tcph->dest) != dst_port)
        return NF_ACCEPT;

    printk(KERN_INFO "TCP %pI4:%u -> %pI4:%u\n",
           &iph->saddr,
           ntohs(tcph->source),
           &iph->daddr,
           ntohs(tcph->dest));

    return NF_ACCEPT;
}

static int __init my_netfilter_init(void)
{
    printk(KERN_INFO "my_netfilter: loaded\n");

    nfho.hook = my_netfilter_hook;
    nfho.pf = PF_INET;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, &nfho)) {
        printk(KERN_ERR "my_netfilter: failed to register hook\n");
        return -EINVAL;
    }

    return 0;
}

static void __exit my_netfilter_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);

    printk(KERN_INFO "netfilter: unloaded\n");
}

module_init(my_netfilter_init);
module_exit(my_netfilter_exit);

