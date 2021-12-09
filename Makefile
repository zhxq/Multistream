KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += streamidtag.o

all:
	make -C $(KERNEL_PATH) M=$(shell pwd) modules
	make -C $(KERNEL_PATH) M=$(shell pwd) modules_install
	depmod -A

clean:
	make -C $(KERNEL_PATH) M=$(shell pwd) clean