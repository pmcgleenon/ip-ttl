# ip-ttl

ttl is a linux netfilter kernel module that rewrites either of the:
  - Diff Serv ECN field.
  - the IP Time To Live (TTL) field or 

# Download:

  $ git clone https://github.com/pmcgleenon/ip-ttl

# Building:

you'll need to install the kernel-devel rpm 

   $ make clean all

# Running: 

Parameters are described with modinfo ttl.ko:

    debug_enabled: Debug mode enabled (int)
    ttl_value: new ttl value (5-255) (int)
    perc_11: percentage of ECN 11 traffic required (0-100) (int)
    perc_10: percentage of ECN 10 traffic required (0-100) (int)
    perc_10: percentage of ECN 01 traffic required (0-100) (int)
    ecn_enabled: Rewrite ECN IP hdr bits (int)
    filter_mode:Behaviour is consistent on 0: Flow Affinity, 1: Source IP Affinity (int)

   
   $ modinfo ttl.ko

you can load the module with no parameters, in which case it will rewrite 100% of the traffic 
with the IP TTL value set to one less than the current default value (i.e. ttl = ttl - 1):

   # insmod ttl.ko 

specify a ttl_value to use this as the TTL; the debug_enabled argument enables debug logs: 

   # insmod ttl.ko debug_enabled=1 ttl_value=40

modify ECN based on Source IP Affinity on with ECN 11, 10, 01 on 20% of the traffic.  ECN 00 will be the remainder (40%)

   # insmod ttl.ko perc11=20 perc10=20 perc01=20 ecn_enabled=1 filter_mode=1


# License

Copyright (C) 2009-2014 The Apache Software Foundation

Licensed under the Apache License, Version 2.0 
