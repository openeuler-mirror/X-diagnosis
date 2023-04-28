obj-m :=rtnlcheck_test.o
KERNEL :=/lib/modules/$(shell uname -r)/build
PWD :=$(shell pwd)
default :
	${MAKE} -C $(KERNEL) M=$(PWD) modules
.PHONEY :clean
clean :
	rm -rf *.ko .tmp_versions .*.cmd *.o *.symvers *.order *.mod *.mod.c */.*.cmd */
