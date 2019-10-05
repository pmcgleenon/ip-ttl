#ifndef __NETFILTER_VERSION_H
#define __NETFILTER_VERSION__H

#include "kern_version.h"

#if IS_RHEL
#if (RHEL_VERSION_LT(7,0))
    #define NF_HOOK_PARAMLIST \
        (\
                 unsigned int hooknum, \
                 struct sk_buff *skb, \
                 const struct net_device *in, \
                 const struct net_device *out, \
                 int (*okfn)(struct sk_buff *) \
             )

    #define NF_HOOKNUM hooknum

#elif (RHEL_VERSION_LT(7,2))
        #define NF_HOOK_PARAMLIST \
            (\
                     const struct nf_hook_ops *ops, \
                     struct sk_buff *skb, \
                     const struct net_device *in, \
                     const struct net_device *out, \
                     int (*okfn)(struct sk_buff *) \
                 )

    #define NF_HOOKNUM ops->hooknum

#else // RHEL 7.2 & 7.3 (might need update to account for possible changes in new releases)
        #define NF_HOOK_PARAMLIST \
            (\
                     const struct nf_hook_ops *ops, \
                     struct sk_buff *skb, \
                     const struct net_device *in, \
                     const struct net_device *out, \
                     const struct nf_hook_state *state \
                 )

    #define NF_HOOKNUM ops->hooknum

#endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
    #define NF_HOOK_PARAMLIST \
        (\
                 unsigned int hooknum, \
                 struct sk_buff *skb, \
                 const struct net_device *in, \
                 const struct net_device *out, \
                 int (*okfn)(struct sk_buff *) \
             )

    #define NF_HOOKNUM hooknum

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
    #define NF_HOOK_PARAMLIST \
        (\
                 const struct nf_hook_ops *ops, \
                 struct sk_buff *skb, \
                 const struct net_device *in, \
                 const struct net_device *out, \
                 int (*okfn)(struct sk_buff *) \
             )

    #define NF_HOOKNUM ops->hooknum

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    #define NF_HOOK_PARAMLIST \
        (\
                 const struct nf_hook_ops *ops, \
                 struct sk_buff *skb, \
                 const struct nf_hook_state *state \
             )

    #define NF_HOOKNUM ops->hooknum

#else
    #define NF_HOOK_PARAMLIST \
        (\
                 void* priv, \
                 struct sk_buff *skb, \
                 const struct nf_hook_state *state \
             )

    #define NF_HOOKNUM state->hook

#endif

#endif
