KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m := rootkit.o
rootkit-objs := main.o hook/hook.o hook/ftrace_helper.o

modules: $(OBJS)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ $^

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@

.PHONY: modules clean