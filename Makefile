# RHEL7 kernels have backported kernel features from 3.13
RH_VER := $(shell /bin/grep -o [0-9].[0-9] /etc/redhat-release) 
RH_MAJVER := $(word 1, $(subst ., ,$(RH_VER)))
RH_MINVER := $(word 2, $(subst ., ,$(RH_VER)))

ifeq ($(RH_MAJVER),7) 
  ifeq ($(RH_MINVER),2)
    EXTRA_CFLAGS += -DRHEL7_2 
  endif
  ifeq ($(RH_MINVER),1)
    EXTRA_CFLAGS += -DRHEL7_1
  endif
endif

obj-m += ttl.o
ccflags-y := $(EXTRA_CFLAGS)

all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
