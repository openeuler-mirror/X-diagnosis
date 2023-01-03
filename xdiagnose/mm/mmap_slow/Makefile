MYMODULE := showbt

ARCH=$(shell uname -m)

ifeq ($(ARCH),aarch64)
    ARCH := arm64
else
    ARCH := x86_64
    CC := gcc
endif

ifdef CUSTOM_LINUX_SRC_PATH
    KDIR := $(CUSTOM_LINUX_SRC_PATH)
else
    KDIR ?= /lib/modules/$(shell uname -r)/build
endif


all: clean default

default:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) modules

clean:
	$(RM) -rf .*.cmd *.o .*.d .*.tmp .*.o *.mod.c *.ko .tmp_versions *.scc *.ld.script *.symvers  *.order


obj-m := $(MYMODULE).o
	showbt-objs := show_bt.o

