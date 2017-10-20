obj-m += mailsteal.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

CFLAGS += $(call cc-option,incompatible-pointer-types ,)