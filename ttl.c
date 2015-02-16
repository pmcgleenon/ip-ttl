/**
   Licensed to the Apache Software Foundation (ASF) under one
   or more contributor license agreements.  See the NOTICE file
   distributed with this work for additional information
   regarding copyright ownership.  The ASF licenses this file
   to you under the Apache License, Version 2.0 (the
   "License"); you may not use this file except in compliance
   with the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.
*/

#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/tcp.h>

#include <net/tcp.h>

MODULE_AUTHOR("Patrick McGleenon");
MODULE_DESCRIPTION("tcp ttl modifier");
MODULE_LICENSE("Apache");
MODULE_VERSION("1.0");

static const char* mod_name = "ttl";
static int debug_enabled = 0;
static int ttl_value = 0;

module_param(debug_enabled, int , S_IRUGO);
MODULE_PARM_DESC(debug_enabled, "Debug mode enabled");

module_param(ttl_value, int , S_IRUGO);
MODULE_PARM_DESC(ttl_value, "new ttl value (5-255)");

static struct nf_hook_ops my_nf_hook;

void do_checksum(struct sk_buff* skb) {
    struct iphdr *iph = NULL;
    struct tcphdr *th = NULL;
    int datalen = 0;

    if (skb_is_nonlinear(skb)) {
        pr_info("%s: NON-LINEAR skb - will attempt to LINEARIZE\n", mod_name);

        if (skb_linearize(skb) != 0) {
            pr_info("%s: FAILED TO LINEARIZE skb\n", mod_name);
            return;
        }
    }

    iph = (struct iphdr*)skb_network_header(skb);
    th = (struct tcphdr*)(skb_network_header(skb) + ip_hdrlen(skb));

    datalen = skb->len - iph->ihl*4;

    th->check = 0;
    th->check = ~tcp_v4_check(datalen, iph->saddr, iph->daddr, 0);

    skb->csum_start = skb_transport_header(skb) - skb->head;

    skb->csum_offset = offsetof(struct tcphdr, check);
    skb->ip_summed = CHECKSUM_PARTIAL;

    ip_send_check(ip_hdr(skb));
}


unsigned int nf_hook_func(
		unsigned int hooknum, 
		struct sk_buff *skb, 
		const struct net_device *in, 
		const struct net_device *out, 
		int (*okfn)(struct sk_buff *)) {

    struct iphdr* iph   = NULL;
    struct tcphdr* tcph = NULL;

    if ( !skb || skb->protocol != htons(ETH_P_IP) || !skb->sk ) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);

    if (iph && iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr*)(skb_network_header(skb) + ip_hdrlen(skb));

	if (ntohs(tcph->source) % 2) {
	    // tcp source port is odd number

	    skb_make_writable(skb, skb->len);

            if (ttl_value) {
                iph->ttl = ttl_value; 
            }
            else {
                iph->ttl -= 1; 
            }

            do_checksum(skb); 
			
	    if (debug_enabled) {
                pr_info("%s: %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d ttl %d len %d", 
		        mod_name,
			NIPQUAD(iph->saddr), ntohs(tcph->source), 
			NIPQUAD(iph->daddr), ntohs(tcph->dest), 
			iph->ttl,
			(skb->len - iph->ihl*4));
            }
        }
    }

    return NF_ACCEPT; 
}

static __init int tcpttl_init(void) {
    my_nf_hook.hook = nf_hook_func;
    my_nf_hook.hooknum = NF_INET_POST_ROUTING;
    my_nf_hook.pf = PF_INET;
    my_nf_hook.priority = NF_IP_PRI_LAST;
    nf_register_hook(&my_nf_hook);

    if (debug_enabled) {
        pr_info("%s: loaded (debug)\n", mod_name);
    }
    else {
        pr_info("%s: loaded\n", mod_name);
    }

    if (ttl_value < 5 || ttl_value > 255) {
        pr_info("%s: rewriting ttl to (ttl - 1)\n", mod_name);
        ttl_value = 0;
    }
    else {
        pr_info("%s: rewriting ttl to %d\n", mod_name, ttl_value);
    } 

    return 0;
}

module_init(tcpttl_init);

static __exit void tcpttl_exit(void) {
    nf_unregister_hook(&my_nf_hook);

    pr_info("%s: unloaded\n", mod_name);
}

module_exit(tcpttl_exit);
