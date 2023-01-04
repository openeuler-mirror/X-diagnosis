MYMODULE := irb

ARCH=$(shell uname -m)

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
	irb-objs := inject_rwsem_block.o

