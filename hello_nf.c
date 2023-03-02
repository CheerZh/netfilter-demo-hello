
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


MODULE_LICENSE("GPLv3");
MODULE_AUTHOR("<cheer.zhang@ucloud.cn>");
MODULE_DESCRIPTION("Hello Netfliter");

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

#define HOOK_PARAM_LIST                                     \
                unsigned int hook, struct sk_buff *skb,     \
                const struct net_device *in,                \
                const struct net_device *out,               \
                int (*okfn)(struct sk_buff*)

static unsigned int hello_pre_routing_hook(HOOK_PARAM_LIST){
    struct iphdr *ip_header;
    ip_header = (struct iphdr *)(skb_network_header(skb));
    printk("@pre_routing: hello '"NIPQUAD_FMT"'\n", NIPQUAD(ip_header->saddr));
    return NF_ACCEPT;
}
static unsigned int hello_local_in_hook(HOOK_PARAM_LIST){
    struct iphdr *ip_header;
    ip_header = (struct iphdr *)(skb_network_header(skb));
    printk("@local_in: welcome '"NIPQUAD_FMT"'\n", NIPQUAD(ip_header->saddr));
    return NF_ACCEPT;
}
static unsigned int hello_forward_hook(HOOK_PARAM_LIST){
    struct iphdr *ip_header;
    ip_header = (struct iphdr *)(skb_network_header(skb));
    printk("@forward: hello again '"NIPQUAD_FMT"', and hi'"NIPQUAD_FMT"'.\n",
        NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr));
    return NF_ACCEPT;
}
static unsigned int hello_local_out_hook(HOOK_PARAM_LIST){
    struct iphdr *ip_header;
    ip_header = (struct iphdr *)(skb_network_header(skb));
    printk("@local_out: hi every one, I'm '"NIPQUAD_FMT"'. \n", NIPQUAD(ip_header->saddr));
    return NF_ACCEPT;
}
static unsigned int hello_post_routing_hook(HOOK_PARAM_LIST){
    struct iphdr *ip_header;
    ip_header = (struct iphdr *)(skb_network_header(skb));
    printk("@post_routing: hi '"NIPQUAD_FMT"' . \n", NIPQUAD(ip_header->daddr));
    return NF_ACCEPT;
}

static struct nf_hook_ops hello_nf_ops[] __read_mostly = {
  {
    .hook = hello_pre_routing_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
  },{
    .hook = hello_local_in_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
  },
  {
    .hook = hello_forward_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_FORWARD,
    .priority = NF_IP_PRI_FIRST,
  },
  {
    .hook = hello_local_out_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
  },
  {
    .hook = hello_post_routing_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FIRST,
  }
};


static int __init init_nf_test(void) {
  int ret;
  ret = nf_register_hooks(hello_nf_ops, ARRAY_SIZE(hello_nf_ops));
  if (ret < 0) {
    printk("register nf hook fail\n");
    return ret;
  }
  printk(KERN_NOTICE "register nf test hook\n");
  return 0;
}

static void __exit exit_nf_test(void) {
  nf_unregister_hooks(hello_nf_ops, ARRAY_SIZE(hello_nf_ops));
}

module_init(init_nf_test);
module_exit(exit_nf_test);

