# ip-ttl

ttl is a linux netfilter kernel module that rewrites the IP Time to Live field.   Currently only
IPv4 is supported

# Building:

you'll need to install the kernel-devel rpm 

   $ make clean all


# Running: 

   $ modinfo ttl.ko

you can load the module with no parameters, in which case it will rewrite the IP TTL value to one
less than the current value (i.e. ttl = ttl - 1)

   $ insmod ttl.ko  debug_enabled=1 ttl_value=40

# License

Copyright (C) 2009-2014 The Apache Software Foundation

Licensed under the Apache License, Version 2.0 
