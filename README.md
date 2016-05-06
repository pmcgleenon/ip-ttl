# ip-ttl

ttl is a linux netfilter kernel module that rewrites the IP Time To Live (TTL) field.
Currently only IPv4 is supported. The TCP/UDP IP packets that are altered are selected based on the
source port - with the percentage of traffic configurable - default is 50% of traffic.

# Download:

  $ git clone https://github.com/pmcgleenon/ip-ttl

# Building:

you'll need to install the kernel-devel rpm 

   $ make clean all

# Running: 

   $ modinfo ttl.ko

you can load the module with no parameters, in which case it will rewrite 50% of the traffic 
with the IP TTL value set to one less than the current default value (i.e. ttl = ttl - 1):

   $ insmod ttl.ko 

specify a ttl_value to use this as the TTL; the debug_enabled argument enables debug logs: 

   $ insmod ttl.ko debug_enabled=1 ttl_value=40

specify a perc value to alter the amount of traffic to apply the new TTL to; ie 25%:

   $ insmod ttl.ko perc=25 ttl_value=40

# License

Copyright (C) 2009-2014 The Apache Software Foundation

Licensed under the Apache License, Version 2.0 
