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

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/tcp.h>
#include <net/tcp.h>

MODULE_AUTHOR("Patrick McGleenon, Darren Todd");
MODULE_DESCRIPTION("ttl/ecn modifier");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.4");

static const int ECN_IP_MASK = 3;
static const int ECN_NOT_ECT = 0;
static const int ECN_ECT_1 = 1;
static const int ECN_ECT_0 = 2;
static const int ECN_CE = 3;

static const char* mod_name = "ttl";
static int debug_enabled = 0;
static int ttl_value = 0;
static int perc = 100;
static int ecn_enabled = 0;
static int filter_mode = 0;

module_param(debug_enabled, int , S_IRUGO);
MODULE_PARM_DESC(debug_enabled, " Debug mode enabled");

module_param(ttl_value, int , S_IRUGO);
MODULE_PARM_DESC(ttl_value, " new ttl value (5-255)");

module_param(perc, int , S_IRUGO);
MODULE_PARM_DESC(perc, " percentage of traffic to change the TTL/ECN (0-100)");

module_param(ecn_enabled, int , S_IRUGO);
MODULE_PARM_DESC(ecn_enabled, " Rewrite ECN IP hdr bits");

module_param(filter_mode, int , S_IRUGO);
MODULE_PARM_DESC(filter_mode, "Behaviour is consistent on 0: Flow Affinity, 1: Source IP Affinity");

void do_tcp_checksum(struct sk_buff* skb) {
    struct iphdr *iph = NULL;
    struct tcphdr *th = NULL;
    int datalen = 0;

    if (skb_is_nonlinear(skb)) {
        if (skb_linearize(skb) != 0) {
            pr_info("%s: FAILED TO LINEARIZE skb\n", mod_name);
            return;
        }
    }

    iph = (struct iphdr*)skb_network_header(skb);
    datalen = skb->len - iph->ihl*4;

    if (iph->protocol == IPPROTO_TCP) {
        th = (struct tcphdr*)(skb_network_header(skb) + ip_hdrlen(skb));
        th->check = 0;
        th->check = ~tcp_v4_check(datalen, iph->saddr, iph->daddr, 0);
    }

    skb->csum_start = skb_transport_header(skb) - skb->head;

    skb->csum_offset = offsetof(struct tcphdr, check);
    skb->ip_summed = CHECKSUM_PARTIAL;

    ip_send_check(ip_hdr(skb));
}

void do_udp_checksum(struct sk_buff* skb) {
    struct iphdr *iph = NULL;
    struct udphdr *uh = NULL;
    int datalen = 0;

    if (skb_is_nonlinear(skb)) {
        if (skb_linearize(skb) != 0) {
            pr_info("%s: FAILED TO LINEARIZE skb\n", mod_name);
            return;
        }
    }

    iph = (struct iphdr*) skb_network_header(skb);
    datalen = skb->len - iph->ihl*4;

    if (iph->protocol == IPPROTO_UDP) {
        uh = (struct udphdr*)(skb_network_header(skb) + ip_hdrlen(skb));
        uh->check = 0;

        uh->check = csum_tcpudp_magic(iph->saddr,
                                  iph->daddr,
                                  datalen,
                                  IPPROTO_UDP,
                                  csum_partial((unsigned char *)uh,
                                               datalen,
                                               0));
    }

    skb->csum_start = skb_transport_header(skb) - skb->head;

    skb->csum_offset = offsetof(struct tcphdr, check);
    skb->ip_summed = CHECKSUM_UNNECESSARY;

    ip_send_check(ip_hdr(skb));
}

void set_ecn_congested(struct iphdr* iph) {
    if (ecn_enabled) {
        __u8 oldtos;

        oldtos = iph->tos;
        iph->tos &= ~ECN_IP_MASK;
        iph->tos |= (ECN_CE & ECN_IP_MASK);
        csum_replace2(&iph->check, htons(oldtos), htons(iph->tos));
    }
}

void set_ecn_congested_ipv6(struct sk_buff* skb) {
    if (ecn_enabled) {
        ipv6_change_dsfield(ipv6_hdr(skb), ECN_IP_MASK, ECN_CE);
    }
}

void set_ecn_not_congested(struct iphdr* iph, u16 sport) {
    if (ecn_enabled) {

        int ecn_not_congested = ((htons(sport) % 3) & ECN_IP_MASK);
        __u8 oldtos;

        oldtos = iph->tos;
        iph->tos &= ~ECN_IP_MASK;
        iph->tos |= (ecn_not_congested & ECN_IP_MASK);
        csum_replace2(&iph->check, htons(oldtos), htons(iph->tos));
    }
}

void set_ecn_not_congested_ipv6(struct sk_buff* skb, u16 sport) {
    if (ecn_enabled) {
        int ecn_not_congested = ((htons(sport) % 3) & ECN_IP_MASK);
        ipv6_change_dsfield(ipv6_hdr(skb), ECN_IP_MASK, ecn_not_congested);
    }
}

int matches_value(uint32_t val, int perc) {

    if (perc == 100) {
        return 1;
    } else if (perc == 0) {
        return 0;
    }

    return ((val % (int)100/(perc)) == 0);
}

int matches_udp(struct udphdr* udph) {
    return matches_value(ntohs(udph->source), perc);
}

int matches_tcp(struct tcphdr* tcph) {
    return ( matches_value(ntohs(tcph->source), perc)); 
}

int matches_ipv4(struct iphdr* iph) {
    return ( matches_value(ntohl(iph->saddr), perc)); 
}

int matches_ipv6(struct ipv6hdr* ip6h) {
    __be32 hash = ip6h->saddr.s6_addr32[0] ^
                  ip6h->saddr.s6_addr32[1] ^
                  ip6h->saddr.s6_addr32[2] ^
                  ip6h->saddr.s6_addr32[3];
    return matches_value(ntohl(hash), perc);
}

int matches_udp_v4_filter(struct udphdr* udph, struct iphdr* iph) {
    return (filter_mode == 0) ? matches_udp(udph) :  matches_ipv4(iph);
}

int matches_tcp_v4_filter(struct tcphdr* tcph, struct iphdr* iph) {
   return (filter_mode == 0) ? matches_tcp(tcph) :  matches_ipv4(iph);
}

int matches_udp_v6_filter(struct udphdr* udph, struct ipv6hdr* ip6h) {
    return (filter_mode == 0) ? matches_udp(udph) :  matches_ipv6(ip6h);
}

int matches_tcp_v6_filter(struct tcphdr* tcph, struct ipv6hdr* ip6h) {
    return (filter_mode == 0) ? matches_tcp(tcph) :  matches_ipv6(ip6h);
}

static unsigned int nf_ipv4_postrouting_hook(
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) 
                unsigned int hooknum,
#else
                const struct nf_hook_ops *ops,
#endif
		struct sk_buff *skb, 
		const struct net_device *in, 
		const struct net_device *out, 
#if defined(RHEL7_2)
        	const struct nf_hook_state *state) {
#else
		int (*okfn)(struct sk_buff *)) {
#endif

    struct iphdr*  iph  = NULL;

    if ( !skb || skb->protocol != htons(ETH_P_IP)) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    if (!iph)  {
        return NF_ACCEPT;
    }

    if (!skb_make_writable(skb, sizeof(struct iphdr))) {
        return NF_ACCEPT;
    }

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr* tcph = tcp_hdr(skb);

	    if ( matches_tcp_v4_filter(tcph, iph) ) {
	        // filter matches

            set_ecn_congested(iph);

            if (ttl_value) {
                iph->ttl = ttl_value; 
                do_tcp_checksum(skb); 
			
	        if (debug_enabled) {
                    pr_info("%s: TCP %pI4:%d -> %pI4:%d ttl %d len %d", 
		        mod_name,
		    	&iph->saddr, ntohs(tcph->source), 
	    		&iph->daddr, ntohs(tcph->dest), 
    			iph->ttl,
    			(skb->len - iph->ihl*4));
                }     
            }
        } else {
            set_ecn_not_congested(iph, tcph->source);
        }
    }

    else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr* udph = udp_hdr(skb);

        if ( matches_udp_v4_filter(udph, iph) ) { 
            // filter matches

            set_ecn_congested(iph);

            if (ttl_value) {
                iph->ttl = ttl_value;
                do_udp_checksum(skb); 

                if (debug_enabled) {
                    pr_info("%s: UDP %pI4:%d -> %pI4:%d ttl %d len %d",
                    mod_name,
                    &iph->saddr, ntohs(udph->source),
                    &iph->daddr, ntohs(udph->dest),
                    iph->ttl,
                    (skb->len - iph->ihl*4));
                }
            }
        } else {
            set_ecn_not_congested(iph, udph->source);
        }
    }

    return NF_ACCEPT; 
}


static unsigned int nf_ipv6_postrouting_hook(
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
                unsigned int hooknum,
#else
                const struct nf_hook_ops *ops,
#endif
                struct sk_buff *skb,
                const struct net_device *in,
                const struct net_device *out,
#if defined(RHEL7_2)
                const struct nf_hook_state *state) {
#else
                int (*okfn)(struct sk_buff *)) {
#endif

    struct ipv6hdr* ip6h  = NULL;

    if ( !skb ) {
        return NF_ACCEPT;
    }

    ip6h = ipv6_hdr(skb);
    if (!ip6h)  {
        return NF_ACCEPT;
    }

    if (!skb_make_writable(skb, sizeof(struct iphdr))) {
        return NF_ACCEPT;
    }

    if (ip6h->nexthdr  == IPPROTO_TCP) {
        struct tcphdr* tcph = tcp_hdr(skb);

        if ( matches_tcp_v6_filter(tcph, ip6h)) {
            // source port modulus matches

            set_ecn_congested_ipv6(skb);

/*
            if (ttl_value) {
                ip6h->hop_limit = ttl_value;
                do_tcp_checksum(skb);

                if (debug_enabled) {
                    pr_info("%s: TCP %pI6:%d -> %pI6:%d ttl %d len %d",
                        mod_name,
                        &ip6h->saddr, ntohs(tcph->source),
                        &ip6h->daddr, ntohs(tcph->dest),
                        ip6h->hop_limit,
	                ntohs(ip6h->payload_len));
                }
            }
*/
        } else {
            set_ecn_not_congested_ipv6(skb, tcph->source);
        }
    }

    else if (ip6h->nexthdr == IPPROTO_UDP) {
        struct udphdr* udph = udp_hdr(skb);

        if ( matches_udp_v6_filter(udph, ip6h)) {
            // source port modulus matches

            set_ecn_congested_ipv6(skb);

/*
            if (ttl_value) {
                ip6h->hop_limit = ttl_value;
                do_udp_checksum(skb);

                if (debug_enabled) {
                    pr_info("%s: UDP %pI4:%d -> %pI4:%d ttl %d len %d",
                    mod_name,
                    &ip6h->saddr, ntohs(udph->source),
                    &ip6h->daddr, ntohs(udph->dest),
                    ip6h->hop_limit,
	            ntohs(ip6h->payload_len));
                }
            }
*/
        } else {
            set_ecn_not_congested_ipv6(skb, udph->source);
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops ipv4_ttl_ops[] __read_mostly = {
    {
        .hook           = nf_ipv4_postrouting_hook,
        .owner          = THIS_MODULE,
        .pf             = NFPROTO_IPV4,
        .hooknum        = NF_INET_POST_ROUTING,
        .priority       = NF_IP_PRI_LAST,
    },
};

static struct nf_hook_ops ipv6_ttl_ops[] __read_mostly = {
    {
        .hook           = nf_ipv6_postrouting_hook,
        .owner          = THIS_MODULE,
        .pf             = NFPROTO_IPV6,
        .hooknum        = NF_INET_POST_ROUTING,
        .priority       = NF_IP_PRI_LAST,
    },
};



static __init int tcpttl_init(void) {
    nf_register_hooks(ipv4_ttl_ops, ARRAY_SIZE(ipv4_ttl_ops));
    nf_register_hooks(ipv6_ttl_ops, ARRAY_SIZE(ipv6_ttl_ops));

    if (debug_enabled) {
        pr_info("%s: loaded (debug) ecn_enabled[%d]\n", mod_name, ecn_enabled);
    }
    else {
        pr_info("%s: loaded ecn_enabled[%d]\n", mod_name, ecn_enabled);
    }

    if (ttl_value > 5 && ttl_value < 255) {
        pr_info("%s: rewriting ttl to %d\n", mod_name, ttl_value);
    }

    if (perc < 1 || perc > 100) {
        pr_info("%s: given percentage of traffic to alter %d is invalid; resetting to 50%%", mod_name, perc);
        perc = 50;
    }
    else {
        pr_info("%s: altering %d%% of traffic\n", mod_name, perc); 
    }

    if (filter_mode != 0 && filter_mode !=1) {
        pr_info("%s: filter_mode can be either 0 (flow) or 1 (IP).  Invalid value: %d \n", mod_name, filter_mode); 
        filter_mode = 0;
    }
    pr_info("%s: using filter_mode %d \n", mod_name, filter_mode); 

    return 0;
}

module_init(tcpttl_init);

static __exit void tcpttl_exit(void) {
    nf_unregister_hooks(ipv4_ttl_ops, ARRAY_SIZE(ipv4_ttl_ops));
    nf_unregister_hooks(ipv6_ttl_ops, ARRAY_SIZE(ipv6_ttl_ops));

    pr_info("%s: unloaded\n", mod_name);
}

module_exit(tcpttl_exit);
