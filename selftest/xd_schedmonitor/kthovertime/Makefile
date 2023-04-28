obj-m := kthovertime.o
KERNEL := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	${MAKE} -C $(KERNEL) M=$(PWD) modules
.PHONEY: clean
clean:
	rm -rf *ko *.o *.cmd *mod* *.order *.symvers .tmp* 
