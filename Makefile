obj-m += nl_k.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Werror -Wall -o nl_u nl_u.c
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	@rm -fr nl_u *.o
