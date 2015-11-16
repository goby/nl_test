
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/semaphore.h>
#include <net/sock.h>

#include "nl.h"

DEFINE_SEMAPHORE(receive_sem);

static struct sock *nlfd;

struct {
    __u32 pid;
    rwlock_t lock;
} user_proc;

static void kernel_receive(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    int len;
    nlh = nlmsg_hdr(skb);
    len = skb->len;

    while(nlmsg_ok(nlh, len)) {
        if (down_trylock(&receive_sem)) {
            return;
        }

        if (nlh->nlmsg_type == NL_U_PID) {
            write_lock_bh(&user_proc.lock);
            user_proc.pid = nlh->nlmsg_pid;
            write_unlock_bh(&user_proc.lock);
        } else if (nlh->nlmsg_type == NL_CLOSE) {
            write_lock_bh(&user_proc.lock);
            if (nlh->nlmsg_pid == user_proc.pid) {
                user_proc.pid = 0;
            }
            write_unlock_bh(&user_proc.lock);
        }

        up(&receive_sem);
        nlh = nlmsg_next(nlh, &len);
    }

}

static int send_to_user(struct packet_info *info)
{
    int ret;
    int size;
    sk_buff_data_t old_tail;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct packet_info *packet;
    
    size = NLMSG_SPACE(sizeof(*info));

    skb = alloc_skb(size, GFP_ATOMIC); 
    old_tail = skb->tail;

    nlh = nlmsg_put(skb, 0, 0, NL_K_MSG, size - sizeof(*nlh), NLM_F_REQUEST);
    if (!nlh) {
        if (skb) {
            kfree_skb(skb);
            return -1;
        }
    }
    packet = NLMSG_DATA(nlh);
    memset(packet, 0, sizeof(struct packet_info));

    packet->src = info->src;
    packet->dst = info->dst;

    nlh->nlmsg_len = skb->tail - old_tail;

    NETLINK_CB(skb).dst_group = 0;

    read_lock_bh(&user_proc.lock);
    ret = netlink_unicast(nlfd, skb, user_proc.pid, MSG_DONTWAIT);
    read_unlock_bh(&user_proc.lock);

    return ret;
}

static unsigned int get_icmp(const struct nf_hook_ops *ops,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff*))
{
    struct iphdr *iph = ip_hdr(skb);
    struct packet_info info;

    if (iph->protocol == IPPROTO_ICMP) {
        read_lock_bh(&user_proc.lock);
        if (user_proc.pid != 0) {
            read_unlock_bh(&user_proc.lock);
            info.src = iph->saddr;
            info.dst = iph->daddr;
            send_to_user(&info);
        } else {
            read_unlock_bh(&user_proc.lock);
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nl_ops = {
    .hook = get_icmp,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER - 1,
};

static int __init nl_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = kernel_receive,
    };

    rwlock_init(&user_proc.lock);
    nlfd = netlink_kernel_create(&init_net, NL_IMP2, &cfg);
    if (!nlfd) {
        printk("can not netlink socket.\n");
        return -1;
    }
    return nf_register_hook(&nl_ops);
}

static void __exit nl_exit(void)
{
    if (nlfd) {
        sock_release(nlfd->sk_socket);
        netlink_kernel_release(nlfd);
    }
    nf_unregister_hook(&nl_ops);
}

module_init(nl_init);
module_exit(nl_exit);
